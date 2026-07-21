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
        # 1. Définition de la cible et de l'objectif selon le stage
        # ==========================================

        if stage == "discovery":

            target_info = f"Network Subnet based on IP {network.get('ip_address')} and Mask {network.get('subnet_mask')}"

            stage_instructions = (
                "STAGE: DISCOVERY\n"
                "Your goal is to discover active hosts on the entire subnet, "
                "WITH version detection and a SYN scan (per audit requirement). "
                "Use flags: -sS -sV, combined with -F to keep the scan fast "
                "enough on a full subnet (avoid full port range scans here). "
                "Example: nmap -sS -sV -F <subnet>. "
                "Do NOT perform a full 1-65535 port scan on the entire subnet."
            )

        else:  # stage == "enumeration"

            discovered_hosts = state.get("discovered_hosts", [])
            current_host_index = state.get("current_host_index", 0)
            current_command_index = state.get("current_command_index", 0)
            commands_per_host = state.get(
                "commands_per_host", DEFAULT_ENUMERATION_COMMANDS
            )

            # Garde-fou défensif : si le Supervisor a un bug de routing et
            # nous appelle hors limites, on échoue explicitement plutôt
            # que de crasher avec un IndexError cryptique plus bas.
            if not discovered_hosts or current_host_index >= len(discovered_hosts):
                raise RuntimeError(
                    "CommandAgent appelé avec current_host_index hors limites "
                    f"({current_host_index} / {len(discovered_hosts)} hosts). "
                    "Le stage devrait être 'done' à ce stade — vérifier le "
                    "routing du Supervisor."
                )

            current_target = discovered_hosts[current_host_index]

            # Quel flag utiliser pour CE tour précis (-sS, -sV, ou -sn...)
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
                    "ports. Combine with -F to keep it fast (top 100 ports)."
                ),
                "-sV": (
                    "Perform a version detection scan (-sV) on this host to "
                    "identify service versions on open ports. Combine with "
                    "-F to keep it fast (top 100 ports)."
                ),
                "-sn": (
                    "Perform a host discovery / ping-only scan (-sn) on "
                    "this single host (no port scan) to confirm it is "
                    "still reachable."
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

- Generate ONLY ONE Nmap command.
- The command MUST start with the word "nmap".
- Never repeat a previous command.
- Use only safe Nmap options.
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
        # On utilise le paramètre "format" d'Ollama avec le schema
        # Pydantic de CommandInfo pour forcer une sortie JSON valide,
        # au lieu de compter uniquement sur les instructions du prompt.

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

        # Sécurité : nettoyage des balises Markdown si Llama3 en génère quand même
        if content.startswith("```json"):
            content = content[7:]
        if content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
        content = content.strip()

        data = json.loads(content)

        # ==========================================
        # 5. Garde-fou : s'assurer que la commande commence par "nmap"
        # ==========================================
        # Le LLM oublie parfois d'inclure "nmap" au début de la
        # commande, ce qui fait échouer le Guardrail (qui interprète
        # alors le premier flag comme "l'outil").

        raw_command = data["command"].strip()

        if not raw_command.lower().startswith("nmap"):
            raw_command = f"nmap {raw_command}"

        # ==========================================
        # 6. Garde-fou : s'assurer que le flag requis pour ce tour
        #    d'énumération (-sS / -sV / -sn) est bien présent.
        # ==========================================
        # Le LLM respecte généralement les instructions, mais llama3
        # peut parfois dériver. On force le flag attendu s'il manque,
        # plutôt que de silencieusement exécuter le mauvais scan.

        if stage == "enumeration" and current_flag not in raw_command:
            raw_command = raw_command.replace("nmap", f"nmap {current_flag}", 1)

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

        # Initialisation sécurisée de l'historique
        if "command_history" not in state:
            state["command_history"] = []

        state["command_history"].append(command.command)

        return state