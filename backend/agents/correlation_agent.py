"""
Vulnerability Correlation Agent (Phase 6).

Correlates discovered services, versions, and tags with potential
security risks (with severity) and recommendations for each host.

Utilise maintenant l'API NVD (backend/tools/nvd_tool.py) pour
récupérer de VRAIS CVE par service/version détecté, et fournit ce
contexte réel au LLM au lieu de le laisser deviner à partir de sa
seule connaissance interne.
"""

import json
import ollama
from backend.models.state import AuditState
from backend.tools.nvd_tool import NvdTool


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

            # --- Recherche de VRAIS CVE via NVD, par service/version ---
            cve_findings = CorrelationAgent._lookup_cves(host)
            cve_context = CorrelationAgent._format_cve_context(cve_findings)

            prompt = f"""
You are an expert cybersecurity vulnerability analyst.
Target IP: {ip}
Discovered Tags: {tags}
Open Ports & Services: {ports_summary}

Real CVE data retrieved from the NVD (National Vulnerability Database) for the
detected service versions above:
{cve_context}

Based on the technologies/versions AND the real CVE data above, produce a structured
security analysis with TWO distinct categories:
1. "risks": concrete security weaknesses or exposures you can justify from the data above
   (e.g. an outdated/vulnerable service version, an unencrypted protocol, an exposed
   management port). PRIORITIZE the real CVE data when relevant — cite the CVE ID
   (e.g. "CVE-2023-XXXXX") inside the description when a risk maps to one of the CVEs
   listed above. Each risk needs a "severity" (Critical, High, Medium, or Low) and a
   "description".
2. "recommendations": actionable hardening advice, not necessarily tied to a specific risk.

If open ports/services list is "None" or very sparse, and no CVE data was found, keep
both lists short and honest — do not invent risks or CVEs you cannot justify from the
data given.

Return ONLY a valid JSON object exactly in this shape:
{{
  "risks": [{{"severity": "High", "description": "..."}}],
  "recommendations": ["..."]
}}
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
                risks = data.get("risks", [])
                recommendations = data.get("recommendations", [])

                # Validation minimale : on ne garde que les entrées bien formées
                clean_risks = [
                    {"severity": r.get("severity", "Medium"), "description": r.get("description", "")}
                    for r in risks
                    if isinstance(r, dict) and r.get("description")
                ]

                state["vulnerabilities"][ip] = {
                    "risks": clean_risks,
                    "recommendations": [r for r in recommendations if r],
                    "cve_sources": [f["cve_id"] for f in cve_findings],
                }
                print(f"  -> Analyse de sécurité pour {ip} générée avec succès "
                      f"({len(clean_risks)} risque(s), {len(recommendations)} recommandation(s), "
                      f"{len(cve_findings)} CVE trouvé(s) via NVD).")

            except Exception as e:
                print(f"  -> Erreur lors de l'analyse pour {ip}: {str(e)}")
                state["vulnerabilities"][ip] = {
                    "risks": [],
                    "recommendations": ["Standard hardening recommended."],
                    "cve_sources": [],
                }

        print("[Correlation Agent] Phase 6 terminée.")
        state["stage"] = "done"
        return state

    @staticmethod
    def _lookup_cves(host) -> list[dict]:
        """
        Interroge NVD pour chaque port/service qui a un service ET une
        version détectés (une recherche vague sans version renvoie trop
        de bruit). Déduplique par cve_id, limite à 10 CVE max par host
        pour ne pas exploser le prompt.
        """
        seen_ids = set()
        findings = []

        for port in host.ports:
            if not port.service or not port.version:
                continue

            keyword = f"{port.service} {port.version}"
            results = NvdTool.search_cves(keyword, max_results=3)

            for cve in results:
                if cve["cve_id"] not in seen_ids:
                    seen_ids.add(cve["cve_id"])
                    findings.append(cve)

            if len(findings) >= 10:
                break

        return findings[:10]

    @staticmethod
    def _format_cve_context(cve_findings: list[dict]) -> str:
        if not cve_findings:
            return "No matching CVE found in NVD for the detected service versions."

        lines = []
        for cve in cve_findings:
            score_str = f" (CVSS {cve['score']})" if cve.get("score") is not None else ""
            lines.append(f"- {cve['cve_id']} [{cve['severity']}]{score_str}: {cve['description']}")

        return "\n".join(lines)