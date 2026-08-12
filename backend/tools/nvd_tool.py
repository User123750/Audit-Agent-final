"""
NVD Tool.

Wrapper autour de l'API NVD (National Vulnerability Database) pour
récupérer de VRAIS CVE liés à un service/version détecté par Nmap,
au lieu de laisser le LLM inventer des risques à partir de sa seule
connaissance interne.

Doc API : https://nvd.nist.gov/developers/vulnerabilities
Endpoint : https://services.nvd.nist.gov/rest/json/cves/2.0

Sans clé API : rate limit ~5 requêtes / 30s.
Avec clé API (NVD_API_KEY) : ~50 requêtes / 30s.
"""

import requests

from backend.config import settings

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NvdTool:

    @staticmethod
    def search_cves(keyword: str, max_results: int = 5) -> list[dict]:
        """
        Cherche les CVE liés à un mot-clé (ex: "OpenSSH 8.2", "Apache 2.4.49").
        Retourne une liste de dicts simplifiés : cve_id, severity, score, description.
        En cas d'erreur réseau/API, retourne une liste vide (fail-safe — la
        correlation continue avec les connaissances internes du LLM en secours).
        """
        if not keyword or not keyword.strip():
            return []

        params = {
            "keywordSearch": keyword.strip(),
            "resultsPerPage": max_results,
        }

        headers = {}
        if settings.NVD_API_KEY:
            headers["apiKey"] = settings.NVD_API_KEY

        try:
            response = requests.get(
                NVD_BASE_URL,
                params=params,
                headers=headers,
                timeout=15,
            )
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as exc:
            print(f"[NvdTool] Erreur API NVD pour '{keyword}': {exc}")
            return []
        except ValueError:
            print(f"[NvdTool] Réponse NVD non-JSON pour '{keyword}'.")
            return []

        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "UNKNOWN")

            descriptions = cve.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                descriptions[0]["value"] if descriptions else "",
            )

            severity, score = NvdTool._extract_severity(cve.get("metrics", {}))

            results.append(
                {
                    "cve_id": cve_id,
                    "severity": severity,
                    "score": score,
                    "description": description[:300],
                }
            )

        return results

    @staticmethod
    def _extract_severity(metrics: dict) -> tuple[str, float | None]:
        """
        Essaie CVSS v3.1, puis v3.0, puis v2 (dans cet ordre de préférence).
        Retourne (severity, score) — severity dans {"Critical","High","Medium","Low"}.
        """
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                score = cvss_data.get("baseScore")
                severity = entries[0].get("baseSeverity") or cvss_data.get("baseSeverity")
                if severity is None and score is not None:
                    severity = NvdTool._score_to_severity(score)
                return (severity or "Medium", score)

        return ("Medium", None)

    @staticmethod
    def _score_to_severity(score: float) -> str:
        if score >= 9.0:
            return "Critical"
        if score >= 7.0:
            return "High"
        if score >= 4.0:
            return "Medium"
        return "Low"