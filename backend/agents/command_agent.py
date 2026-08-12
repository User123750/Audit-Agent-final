"""
Command Agent.

Generates a safe Nmap command using Ollama.
Adapts dynamically to the audit stage (discovery vs enumeration)
and integrates human feedback.
"""

import json

import ollama

from backend.models.command import (
    CommandArgument,
    CommandInfo,
    RiskLevel,
)
from backend.models.state import AuditState, DEFAULT_ENUMERATION_COMMANDS
from backend.prompts.command_prompt import COMMAND_PROMPT


class CommandAgent:

    MODEL = "llama3"

    @classmethod
    def run(cls, state: AuditState) -> AuditState:

        network = state.get("network_info", {})
        previous_commands = "\n".join(state.get("command_history", []))

        stage = state.get("stage", "discovery")

        # ==========================================
        # 0. Gestion de la phase Classification
        # ==========================================
        if stage == "classification":
            # Le CommandAgent n'a pas besoin de générer de commandes réseau en phase de classification
            state["current_command"] = None
            return state

        # ==========================================
        # 1. Définition de la cible et de l'objectif selon le stage
        # ==========================================

        os_family = "unknown"

        if stage == "discovery":

            target_info = f"Network Subnet based on IP {network.get('ip_address')} and Mask {network.get('subnet_mask')}"

            stage_instructions = (
                "STAGE: DISCOVERY\n"
                "Your goal is to discover active hosts on the entire subnet, "
                "WITH version detection and a SYN scan (per audit requirement). "
                "Use flags: -sS -sV, combined with -F to keep the scan fast "
                "enough on a full subnet (avoid full port range scans here). "
                "Also add -T4 (faster timing template, still safe/reliable — "
                "NOT the forbidden -T5) and -n (skip reverse DNS lookups, "
                "which otherwise add delay per host). "
                "Example: nmap -sS -sV -F -T4 -n <subnet>. "
                "Do NOT perform a full 1-65535 port scan on the entire subnet."
            )

        elif stage == "enumeration":

            discovered_hosts = state.get("discovered_hosts", [])
            current_host_index = state.get("current_host_index", 0)
            current_command_index = state.get("current_command_index", 0)
            commands_per_host = state.get(
                "commands_per_host", DEFAULT_ENUMERATION_COMMANDS
            )

            if not discovered_hosts or current_host_index >= len(discovered_hosts):
                raise RuntimeError(
                    "CommandAgent appelé avec current_host_index hors limites "
                    f"({current_host_index} / {len(discovered_hosts)} hosts). "
                    "Le stage devrait être 'done' à ce stade — vérifier le "
                    "routing du Supervisor."
                )

            current_target = discovered_hosts[current_host_index]

            if current_command_index >= len(commands_per_host):
                raise RuntimeError(
                    "CommandAgent appelé avec current_command_index hors "
                    f"limites ({current_command_index} / {len(commands_per_host)})."
                )

            current_flag = commands_per_host[current_command_index]

            target_info = f"Single Target IP: {current_target}"

            flag_instructions = {
                "-sS": (
                    "Perform a SYN scan (-sS) on this host to identify open "
                    "ports. Combine with -F to keep it fast (top 100 ports), "
                    "plus -T4 (faster, still reliable timing) and -n (skip "
                    "reverse DNS lookups)."
                ),
                "-sV": (
                    "Perform a version detection scan (-sV) on this host to "
                    "identify service versions on open ports. Combine with "
                    "-F to keep it fast (top 100 ports), plus -T4 and -n."
                ),
                "-sn": (
                    "Perform a host discovery / ping-only scan (-sn) on "
                    "this single host (no port scan) to confirm it is "
                    "still reachable. Add -n to skip reverse DNS lookups."
                ),
                "-O": (
                    "Perform OS detection (-O) on this host to identify "
                    "the operating system family and version, along with "
                    "Nmap's confidence percentage for each guess. This "
                    "requires no additional port-scan flags — just -O "
                    "alone on the target (e.g. 'nmap -O --max-os-tries=1 -n "
                    "<target>'). --max-os-tries=1 stops Nmap from retrying "
                    "its OS fingerprint guesses multiple times, which is "
                    "the main reason -O is slow — one try is enough since "
                    "we already report the confidence percentage. "
                    "Do NOT combine -O with -F or a port range."
                ),
            }.get(
                current_flag,
                f"Perform a scan using the {current_flag} option on this host.",
            )

            stage_instructions = (
                "STAGE: ENUMERATION\n"
                f"Your goal is to perform ONE SPECIFIC scan on THIS SINGLE "
                f"TARGET: {current_target}.\n"
                f"Required scan for this turn ({current_command_index + 1}/"
                f"{len(commands_per_host)}): {flag_instructions}\n"
                f"The command MUST use the '{current_flag}' option as its "
                "primary flag for this turn — do not substitute a "
                "different scan type.\n"
                "NEVER use -p- or -p 1-65535 or any full port range scan — "
                "this takes 20-30+ minutes on a single host and is NOT "
                "acceptable for this stage.\n"
                "Only scan all 65535 ports if the engineer explicitly "
                "requested a full scan via feedback.\n"
                "Do NOT scan the entire subnet — target ONLY this single IP."
            )

        elif stage == "identity_collection":
            discovered_hosts = state.get("discovered_hosts", [])

            # L'IdentityAgent a déjà incrémenté l'index, la cible actuelle est l'index - 1
            host_idx = state.get("current_host_index", 1) - 1
            if host_idx >= 0 and host_idx < len(discovered_hosts):
                current_target = discovered_hosts[host_idx]
            else:
                current_target = "Unknown SSH Target"

            target_info = f"SSH Session on Target IP: {current_target}"

            # OS déjà détecté par Nmap (-O / -sV), résolu par IdentityAgent.
            # On ne laisse plus le LLM deviner l'OS via le feedback.
            os_family = state.get("detected_os_family", "unknown")

            if os_family == "windows":
                os_instruction = (
                    "The target's OS has been DETECTED as WINDOWS (via Nmap). "
                    "You MUST propose 'systeminfo' as the command."
                )
            elif os_family == "linux":
                os_instruction = (
                    "The target's OS has been DETECTED as LINUX (via Nmap). "
                    "You MUST propose 'cat /etc/os-release' (fallback: 'uname -a' "
                    "or 'hostnamectl') as the command."
                )
            else:
                os_instruction = (
                    "The target's OS could not be confidently detected by Nmap. "
                    "Default to a Linux command ('cat /etc/os-release'), unless "
                    "the engineer's feedback below says otherwise."
                )

            stage_instructions = (
                "STAGE: IDENTITY COLLECTION (Phase 3)\n"
                f"Your goal is to propose ONE safe command via SSH to identify the Operating System of {current_target}.\n"
                f"{os_instruction}\n"
                "Do NOT use Nmap here. You are already executing a local command inside the machine via SSH.\n"
                "Do NOT use forbidden characters for injection like ';', '&', '|', '>', '<'. Keep it to a single safe command."
            )
        else:
            stage_instructions = "STAGE: GENERAL\nPerform the requested operation safely."

        # ==========================================
        # 2. Intégration du feedback de l'ingénieur (Modify)
        # ==========================================

        feedback_section = ""
        validation = state.get("validation")
        if validation and validation.action == "Modify" and validation.comments:
            feedback_section = (
                "================================================\n"
                "ENGINEER FEEDBACK (CRITICAL)\n\n"
                "The human engineer REJECTED your previous command and requested the following modification:\n"
                f"\"{validation.comments}\"\n\n"
                "You MUST apply this modification to your new command.\n"
                "================================================\n"
            )

        # ==========================================
        # 3. Construction du Prompt Final
        # ==========================================

        prompt = f"""
{COMMAND_PROMPT}

================================================
{stage_instructions}
================================================

Network Information
IP Address  : {network.get("ip_address")}
Subnet Mask : {network.get("subnet_mask")}
Gateway     : {network.get("gateway")}

Target to scan : {target_info}

{feedback_section}
================================================

Previously Generated Commands
{previous_commands if previous_commands else "None"}

================================================

Rules

- Generate ONLY ONE command.
- Never repeat a previous command.
- The command must strictly target: {target_info}.
- Return ONLY a valid JSON object.

Expected JSON format:

{{
    "command":"...",
    "objective":"...",
    "description":"...",
    "arguments":[
        {{
            "argument":"...",
            "explanation":"..."
        }}
    ],
    "risk_level":"Low",
    "impact":"...",
    "estimated_duration":"...",
    "justification":"..."
}}

Do not add markdown.
Do not add explanations.
Do not write anything outside the JSON.
"""

        # ==========================================
        # 4. Appel au LLM avec JSON schema enforcement
        # ==========================================

        response = ollama.chat(
            model=cls.MODEL,
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            format=CommandInfo.model_json_schema(),
        )

        content = response["message"]["content"].strip()

        if content.startswith("```json"):
            content = content[7:]
        if content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
        content = content.strip()

        data = json.loads(content)

        # ==========================================
        # 5. Garde-fou : Post-traitement conditionnel
        # ==========================================

        raw_command = data["command"].strip()

        # Le forçage du préfixe 'nmap' ne s'applique qu'aux phases réseau
        if stage in ["discovery", "enumeration"]:
            if not raw_command.lower().startswith("nmap"):
                raw_command = f"nmap {raw_command}"

            # S'assurer que le flag requis est bien présent
            if stage == "enumeration" and current_flag not in raw_command:
                raw_command = raw_command.replace("nmap", f"nmap {current_flag}", 1)

        # Garde-fou identity_collection : si le LLM ignore la détection OS
        # (et que l'ingénieur n'a pas explicitement demandé autre chose via
        # Modify), on force la commande correcte.
        if stage == "identity_collection" and os_family in ("windows", "linux"):
            has_modify_feedback = (
                validation is not None
                and validation.action == "Modify"
                and validation.comments
            )
            if not has_modify_feedback:
                lower_cmd = raw_command.lower()
                if os_family == "windows" and "systeminfo" not in lower_cmd:
                    raw_command = "systeminfo"
                elif os_family == "linux" and not any(
                    marker in lower_cmd for marker in ("os-release", "uname", "hostnamectl")
                ):
                    raw_command = "cat /etc/os-release"

        command = CommandInfo(
            command=raw_command,
            objective=data["objective"],
            description=data["description"],
            arguments=[
                CommandArgument(
                    argument=arg["argument"],
                    explanation=arg["explanation"],
                )
                for arg in data.get("arguments", [])
            ],
            risk_level=RiskLevel(data["risk_level"]),
            impact=data["impact"],
            estimated_duration=data["estimated_duration"],
            justification=data["justification"],
        )

        state["current_command"] = command

        # CORRECTION : chaque nouvelle commande générée doit repartir sur un
        # guardrail/validation "propre" — sinon un Blocked/Reject/Modify de la
        # commande précédente reste collé au state et fausse le routing du
        # Supervisor pour la nouvelle commande (boucle infinie).
        state["guardrail_status"] = None
        state["validation"] = None

        if "command_history" not in state:
            state["command_history"] = []

        state["command_history"].append(command.command)

        return state