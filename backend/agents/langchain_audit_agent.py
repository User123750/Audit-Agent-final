"""
New LangChain-based OddNet audit agent.

The existing LangGraph pipeline is NOT modified or removed.
This agent is introduced in parallel for migration.
"""

import platform

from langchain.agents import create_agent
from langchain.agents.middleware import HumanInTheLoopMiddleware
from langchain_ollama import ChatOllama
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command
from backend.config import settings
from backend.tools.langchain_tools import LANGCHAIN_TOOLS
from backend.tools.ipconfig_tool import IPConfigTool
from backend.tools.ifconfig_tool import IfconfigTool
from backend.utils.netmask_utils import build_subnet_cidr


SYSTEM_PROMPT = """
You are the OddNet network audit assistant.

You assist with authorized infrastructure security audits. You run the
FULL audit workflow autonomously, one host at a time, using ONLY the
tools available to you. Never invent tool results or shell commands.

FULL WORKFLOW (follow this order for every audit):

1. DISCOVERY
   Call run_nmap_discovery once on the given subnet to get the list of
   live hosts. Do this only once per audit.

2. FOR EACH DISCOVERED HOST, IN ORDER, one host at a time:
   a. run_nmap_syn_scan(target) — find open TCP ports.
   b. run_nmap_version_scan(target) — identify service versions on the
      open ports found above.
   c. run_nmap_os_detection(target) — identify the OS family.
   d. If the host exposes SSH (port 22 open) AND you were given SSH
      credentials to use, call run_identity_command(target, os_family)
      with the os_family you inferred from run_nmap_os_detection
      (one of: linux, windows, unknown). If port 22 is not open, or you
      have no reason to believe SSH is usable, SKIP this step for that
      host — do not call it speculatively.
   e. classify_asset(target, nmap_data, ssh_output) — pass it the raw
      combined output of the previous nmap scans for this host as
      nmap_data, and the SSH output (or empty string if step d was
      skipped) as ssh_output. This tool needs NO human approval.
   f. For each interesting service/version you identified in step b
      (e.g. "OpenSSH 8.2", "Apache 2.4.49"), call
      lookup_cve(keyword) to find real known vulnerabilities. Skip
      generic/unversioned services where a meaningful CVE search isn't
      possible. This tool needs NO human approval.

3. Move to the next discovered host and repeat step 2, until every
   discovered host has been processed.

4. FINAL REPORT
   Once every host has been processed, write a single structured
   summary covering, per host: IP, asset class (from classify_asset),
   OS family, open ports/services, and any CVEs found — followed by an
   overall risk summary (counts of hosts with known CVEs, most
   concerning findings first).

IMPORTANT RULES:
- Never invent tool results. Only report what the tools actually
  returned.
- Never invent shell commands — you only ever call the tools provided
  to you, with the arguments they expect.
- run_nmap_discovery, run_nmap_syn_scan, run_nmap_version_scan,
  run_nmap_ping_scan, run_nmap_os_detection and run_identity_command
  all require human approval before execution — always call them and
  wait, never assume approval.
- lookup_cve and classify_asset are read-only and require no approval.
- If a host is unreachable or a scan fails, note it in the final report
  and move on to the next host rather than stopping the whole audit.
- Keep going through ALL discovered hosts before producing the final
  report — do not stop after the first host.
"""


def build_langchain_audit_agent():
    """
    Build the new LangChain audit agent with human approval
    before risky tool execution.
    """

    model = ChatOllama(
        model=settings.OLLAMA_MODEL,
        base_url=settings.OLLAMA_HOST,
        temperature=0,
        # CORRECTIF : Ollama utilise par défaut une fenêtre de contexte
        # très petite (2048-4096 tokens) et tronque silencieusement le
        # début du contexte au-delà — le modèle "oublie" alors les
        # instructions du system prompt et se met à décrire les tool
        # calls en texte au lieu de les exécuter réellement. On agrandit
        # explicitement la fenêtre pour tenir le system prompt détaillé
        # + les résultats de discovery (potentiellement longs).
        num_ctx=8192,
    )

    interrupt_on = {
        "run_nmap_discovery": {
            "allowed_decisions": ["approve", "reject", "edit"]
        },
        "run_nmap_syn_scan": {
            "allowed_decisions": ["approve", "reject", "edit"]
        },
        "run_nmap_version_scan": {
            "allowed_decisions": ["approve", "reject", "edit"]
        },
        "run_nmap_ping_scan": {
            "allowed_decisions": ["approve", "reject", "edit"]
        },
        "run_nmap_os_detection": {
            "allowed_decisions": ["approve", "reject", "edit"]
        },
        "run_identity_command": {
            "allowed_decisions": ["approve", "reject", "edit"]
        },
    }

    hitl = HumanInTheLoopMiddleware(
        interrupt_on=interrupt_on,
        description_prefix="Validation humaine requise avant exécution",
    )

    checkpointer = InMemorySaver()

    agent = create_agent(
        model=model,
        tools=LANGCHAIN_TOOLS,
        system_prompt=SYSTEM_PROMPT,
        middleware=[hitl],
        checkpointer=checkpointer,
    )

    return agent


def detect_local_subnet() -> str:
    """
    Auto-détection du subnet local, comme le faisait NetworkAgent dans
    l'ancien pipeline (ipconfig sous Windows, ifconfig sous Linux).
    Retourne directement une notation CIDR (ex: 192.168.3.0/24) —
    jamais IP/masque brut, qui n'est pas compris par nmap.
    """
    if platform.system() == "Windows":
        network = IPConfigTool.run()
    else:
        network = IfconfigTool.run()

    return build_subnet_cidr(network["ip_address"], network["subnet_mask"])


def run_cli():
    """
    CLI test for the new LangChain agent with HITL.

    The existing LangGraph workflow is not used here.
    """

    agent = build_langchain_audit_agent()

    config = {
        "configurable": {
            "thread_id": "oddnet-cli-test-001"
        }
    }

    print("=" * 70)
    print("ODDNET - LangChain Audit Agent")
    print("=" * 70)

    # CORRECTIF : on ne demande plus le subnet à la main — on le
    # détecte automatiquement, comme le faisait NetworkAgent dans
    # l'ancien pipeline LangGraph.
    subnet = detect_local_subnet()
    print(f"\nSubnet détecté automatiquement : {subnet}")

    use_ssh = input(
        "Utiliser des credentials SSH pour la collecte d'identité si "
        "possible ? (y/n) : "
    ).strip().lower() == "y"

    ssh_instruction = (
        "SSH credentials ARE available in the environment — use "
        "run_identity_command on hosts exposing SSH (port 22) as "
        "described in your instructions."
        if use_ssh else
        "SSH credentials are NOT available — skip run_identity_command "
        "entirely for this audit, even on hosts exposing SSH."
    )

    user_message = f"""
Start a full authorized network audit on subnet {subnet}.

{ssh_instruction}

Follow your full workflow: discovery, then for every discovered host —
port scan, version scan, OS detection, optional identity collection,
classification, and CVE lookup — then produce the final structured
report covering all hosts.
"""

    result = agent.invoke(
        {
            "messages": [
                {
                    "role": "user",
                    "content": user_message,
                }
            ]
        },
        config=config,
        version="v2",
    )

    batch_approved = False

    while result.get("__interrupt__"):
        interrupt = result["__interrupt__"][0]
        interrupt_value = interrupt.value

        action_requests = interrupt_value["action_requests"]

        print("\n" + "=" * 70)
        print("VALIDATION HUMAINE REQUISE")
        print("=" * 70)

        decisions = []

        for action in action_requests:

            if batch_approved:
                print(f"\n[Auto-approuvé] {action['name']} {action['args']}")
                decisions.append({
                    "type": "approve"
                })
                continue

            print(f"\nTool       : {action['name']}")
            print(f"Arguments  : {action['args']}")
            print(f"Description: {action['description']}")

            print("\n1. Approve")
            print("2. Reject")
            print("3. Edit")
            print("4. Approve tout le reste automatiquement (batch)")

            choice = input("Votre choix : ").strip()

            if choice == "1":
                decisions.append({
                    "type": "approve"
                })

            elif choice == "4":
                batch_approved = True
                decisions.append({
                    "type": "approve"
                })

            elif choice == "2":
                reason = input(
                    "Pourquoi rejeter cette action ? "
                ).strip()

                decisions.append({
                    "type": "reject",
                    "message": reason or "Action rejetée par l'utilisateur."
                })

            elif choice == "3":
                print(
                    "\nModification manuelle des arguments."
                )

                print(
                    "Arguments actuels :",
                    action["args"]
                )

                if action["name"] in {
                    "run_nmap_discovery",
                    "run_nmap_syn_scan",
                }:
                    new_value = input(
                        "Nouvelle cible/subnet : "
                    ).strip()

                    if action["name"] == "run_nmap_discovery":
                        edited_args = {
                            "subnet": new_value
                        }
                    else:
                        edited_args = {
                            "target": new_value
                        }

                    decisions.append({
                        "type": "edit",
                        "edited_action": {
                            "name": action["name"],
                            "args": edited_args,
                        }
                    })

                else:
                    print(
                        "Modification non implémentée pour ce tool."
                    )

                    decisions.append({
                        "type": "reject",
                        "message": "Modification non supportée dans ce CLI."
                    })

            else:
                print("Choix invalide. Action rejetée.")

                decisions.append({
                    "type": "reject",
                    "message": "Choix invalide dans le CLI."
                })

        result = agent.invoke(
            Command(
                resume={
                    "decisions": decisions
                }
            ),
            config=config,
            version="v2",
        )

    print("\n" + "=" * 70)
    print("AUDIT TERMINÉ")
    print("=" * 70)

    messages = result["messages"]

    if messages:
        print(messages[-1].content)


if __name__ == "__main__":
    run_cli()