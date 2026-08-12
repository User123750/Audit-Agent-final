"""
Classification Agent (Phase 4).

Uses the LLM to analyze Nmap results and SSH identity output,
then assigns exactly ONE predefined asset class to each host.
"""

import json
import ollama

from backend.models.state import AuditState
from backend.models.classification import HostClassification

class ClassificationAgent:

    MODEL = "llama3"

    @staticmethod
    def run(state: AuditState) -> AuditState:
        print("\n[Classification Agent] Démarrage de la Phase 4 : Classification Refinement...\n")

        if "classifications" not in state:
            state["classifications"] = {}

        discovered = state.get("discovered_hosts", [])
        structured_hosts = state.get("structured_hosts", {})
        host_results = state.get("host_results", {})

        for ip in discovered:
            print(f"[Classification Agent] Analyse de l'hôte {ip}...")

            # 1. Préparation des données factuelles pour le LLM
            host_info = structured_hosts.get(ip)

            # CORRECTION : si aucune donnée Nmap structurée n'existe pour cet
            # hôte (commande rejetée, timeout, erreur d'exécution...), on ne
            # laisse PAS le LLM deviner une classe sans preuve — on le classe
            # directement "Unknown" avec une justification honnête, et on
            # passe à l'hôte suivant sans appeler le LLM.
            if host_info is None:
                state["classifications"][ip] = "Unknown"
                print(f"  -> Résultat : Unknown (aucune donnée Nmap disponible pour {ip})\n")
                continue

            ports_str = ", ".join([f"{p.port}/{p.protocol} ({p.service})" for p in host_info.ports])
            nmap_data = (
                f"MAC Address: {host_info.mac_address}\n"
                f"Vendor: {host_info.vendor}\n"
                f"Open Ports: {ports_str if ports_str else 'None detected'}\n"
            )

            # L'output SSH de la phase 3 a été archivé sous la clé IP
            ssh_output = host_results.get(ip, "Aucun résultat SSH (Identity Collection) disponible.")

            # 2. Construction du Prompt strict avec règles pour les routeurs/firewalls
            prompt = f"""
You are an expert network security auditor.
Your task is to classify the following network asset into EXACTLY ONE of the predefined classes.

Target IP: {ip}

--- FACTUAL DATA COLLECTED ---
Nmap Scan Data:
{nmap_data}

SSH Identity Output (Phase 3):
{ssh_output}
------------------------------

Classification Rules:
- You must assign exactly ONE class from this list: Linux Endpoint, Windows Endpoint, Mac Endpoint, Single Server, Hypervisor, Unknown.
- You are strictly FORBIDDEN to create new classes.
- If the Nmap data indicates network equipment, a router, a firewall (e.g., FortiOS, FortiSSH), or if SSH access failed/is unavailable for a gateway, you MUST classify it as "Unknown".
- If the OS is Linux and it hosts multiple enterprise services (like HTTP, PostgreSQL, SMB), consider it a "Single Server".
- If the SSH identity clearly says Ubuntu/Debian with standard endpoint ports, it's a "Linux Endpoint".

Return ONLY a valid JSON object matching the requested schema with both 'assigned_class' and a non-empty 'justification'. No markdown, no explanations outside the JSON.
"""

            # 3. Appel à Ollama avec format forcé
            try:
                response = ollama.chat(
                    model=ClassificationAgent.MODEL,
                    messages=[
                        {
                            "role": "user",
                            "content": prompt,
                        }
                    ],
                    format=HostClassification.model_json_schema(),
                )

                content = response["message"]["content"].strip()
                if content.startswith("```json"):
                    content = content[7:]
                if content.startswith("```"):
                    content = content[3:]
                if content.endswith("```"):
                    content = content[:-3]

                data = json.loads(content.strip())

                # Validation Pydantic
                classification = HostClassification(**data)

                state["classifications"][ip] = classification.assigned_class.value

                print(f"  -> Résultat : {classification.assigned_class.value}")
                print(f"  -> Justification : {classification.justification}\n")

            except Exception as e:
                print(f"  -> Erreur de classification pour {ip}: {str(e)}")
                state["classifications"][ip] = "Unknown"

        print("[Classification Agent] Phase 4 terminée.")

        # CORRECTION : enchaîner sur la Phase 5 (Collector) au lieu de
        # terminer directement le pipeline — Collector et Correlation
        # existent et attendent d'être exécutés.
        state["stage"] = "collector"

        return state