"""
Vulnerability Correlation Agent (Phase 6).

Correlates discovered services, versions, and tags with potential vulnerabilities
or security recommendations for each host.
"""

import json
import ollama
from backend.models.state import AuditState

class CorrelationAgent:

    MODEL = "llama3"

    @staticmethod
    def run(state: AuditState) -> AuditState:
        print("\n[Correlation Agent] Démarrage de la Phase 6 : Vulnerability Correlation & Risk Analysis...\n")

        if "vulnerabilities" not in state:
            state["vulnerabilities"] = {}

        structured_hosts = state.get("structured_hosts", {})
        asset_tags = state.get("asset_tags", {})

        for ip, host in structured_hosts.items():
            print(f"[Correlation Agent] Analyse des risques pour l'hôte {ip}...")

            tags = asset_tags.get(ip, [])
            ports_summary = ", ".join([f"{p.port}/{p.service} ({p.version})" for p in host.ports]) if host.ports else "None"

            prompt = f"""
You are an expert cybersecurity vulnerability analyst.
Target IP: {ip}
Discovered Tags: {tags}
Open Ports & Services: {ports_summary}

Based on these technologies and versions, identify potential security risks, misconfigurations, or relevant CVE categories (if any are known for these versions), and provide brief security recommendations.

Return ONLY a valid JSON object with a single key "analysis" containing an array of strings (recommendations/risks). Example:
{{"analysis": ["Ensure Nginx is updated to patch recent advisories", "Disable anonymous Samba shares if not needed", "Restrict PostgreSQL port 5432 to trusted internal networks"]}}

No markdown, no explanations outside the JSON.
"""

            try:
                response = ollama.chat(
                    model=CorrelationAgent.MODEL,
                    messages=[{"role": "user", "content": prompt}],
                )

                content = response["message"]["content"].strip()
                if content.startswith("```json"):
                    content = content[7:]
                if content.startswith("```"):
                    content = content[3:]
                if content.endswith("```"):
                    content = content[:-3]

                content = content.strip()
                start_idx = content.find("{")
                end_idx = content.rfind("}")
                if start_idx != -1 and end_idx != -1:
                    content = content[start_idx:end_idx+1]

                data = json.loads(content)
                analysis = data.get("analysis", ["No specific vulnerabilities flagged."])

                state["vulnerabilities"][ip] = analysis
                print(f"  -> Analyse de sécurité pour {ip} générée avec succès.")

            except Exception as e:
                print(f"  -> Erreur lors de l'analyse pour {ip}: {str(e)}")
                state["vulnerabilities"][ip] = ["Standard hardening recommended."]

        print("[Correlation Agent] Phase 6 terminée.")
        state["stage"] = "done"
        return state