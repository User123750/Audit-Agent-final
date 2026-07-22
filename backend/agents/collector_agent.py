"""
Collector Agent (Phase 5).

Discovers dynamic tags based on open ports and services,
and prepares detailed collection targets for the asset.
"""

import json
import ollama

from backend.models.state import AuditState

class CollectorAgent:

    MODEL = "llama3"

    @staticmethod
    def run(state: AuditState) -> AuditState:
        print("\n[Collector Agent] Démarrage de la Phase 5 : Tag Discovery & Detailed Collection...\n")

        if "asset_tags" not in state:
            state["asset_tags"] = {}

        discovered = state.get("discovered_hosts", [])
        structured_hosts = state.get("structured_hosts", {})
        classifications = state.get("classifications", {})

        for ip in discovered:
            print(f"[Collector Agent] Analyse des tags et collectors pour l'hôte {ip}...")

            host_info = structured_hosts.get(ip)
            asset_class = classifications.get(ip, "Unknown")

            ports_str = ""
            if host_info and host_info.ports:
                ports_str = ", ".join([f"{p.port} ({p.service}: {p.version})" for p in host_info.ports])

            # Prompt pour découvrir les tags dynamiques selon l'architecture (Section 5.3)
            prompt = f"""
You are an expert cybersecurity asset profiler.
Your task is to analyze the collected information for target IP: {ip}
Assigned Asset Class: {asset_class}
Open Ports & Services: {ports_str if ports_str else "None"}

Based on these facts, generate a list of relevant technical tags describing the technologies, services, or OS versions running on this asset (e.g., ubuntu, nginx, postgresql, samba, web-server, database).

Return ONLY a valid JSON object with a single key "tags" containing an array of strings. Example:
{{"tags": ["ubuntu", "nginx", "postgresql"]}}

No markdown, no explanations outside the JSON.
"""

            try:
                response = ollama.chat(
                    model=CollectorAgent.MODEL,
                    messages=[{"role": "user", "content": prompt}],
                )

                content = response["message"]["content"].strip()
                if content.startswith("```json"):
                    content = content[7:]
                if content.startswith("```"):
                    content = content[3:]
                if content.endswith("```"):
                    content = content[:-3]

                # Extraction robuste du JSON pour éviter les erreurs de syntaxe
                content = content.strip()
                start_idx = content.find("{")
                end_idx = content.rfind("}")
                if start_idx != -1 and end_idx != -1:
                    content = content[start_idx:end_idx+1]

                data = json.loads(content)
                tags = data.get("tags", [])

                state["asset_tags"][ip] = tags
                print(f"  -> Tags découverts pour {ip} : {tags}")

            except Exception as e:
                print(f"  -> Erreur lors de la découverte des tags pour {ip}: {str(e)}")
                state["asset_tags"][ip] = ["unknown-tech"]

        print("[Collector Agent] Phase 5 (Tag Discovery) terminée.")
        
        # On fait avancer le stage vers la fin
        state["stage"] = "done"

        return state