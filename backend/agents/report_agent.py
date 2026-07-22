"""
Report Agent.

Responsible for generating partial reports (discovery scan, or a
single enumerated host/command) and, at the end of the pipeline,
the final synthesis report consolidating everything, host by host,
using the structured (deduplicated) HostResult data.
"""

from backend.models.report import ReportInfo
from backend.models.command import CommandInfo, RiskLevel
from backend.models.validation import ValidationInfo
from backend.models.state import get_current_key


class ReportAgent:

    @staticmethod
    def run(state):

        if state.get("stage") == "done":
            return ReportAgent._generate_final_report(state)

        return ReportAgent._generate_partial_report(state)

    # ==========================================
    # Partial report (discovery OR one enum command) — unchanged
    # ==========================================

    @staticmethod
    def _generate_partial_report(state):

        key = get_current_key(state)

        print(f"\n[Report Agent] Generating partial report for '{key}'...\n")

        report = ReportInfo(
            audit=state["audit"],
            network_information=state["network_info"],
            approved_command=state["current_command"],
            validation=state["validation"],
            execution_output=state["execution_output"]
        )

        if "partial_reports" not in state:
            state["partial_reports"] = {}

        state["partial_reports"][key] = report

        return state

    # ==========================================
    # Final synthesis report — now host-by-host, deduplicated
    # ==========================================

    @staticmethod
    def _generate_final_report(state):

        print("\n[Report Agent] Generating final synthesis report...\n")

        audit = state["audit"]
        network = state["network_info"]
        discovered = state.get("discovered_hosts", [])
        structured_hosts = state.get("structured_hosts", {})
        asset_tags = state.get("asset_tags", {})
        vulnerabilities = state.get("vulnerabilities", {})  # Récupération des analyses de sécurité (Phase 6)

        sections = []
        sections.append("========== ODDNET AUDIT FINAL REPORT ==========\n")

        sections.append(f"Network Target : {network.get('ip_address')}/{network.get('subnet_mask')}")
        sections.append(f"Gateway        : {network.get('gateway')}")
        sections.append(
            f"Hosts found    : {len(discovered)} "
            f"({', '.join(discovered) if discovered else 'None'})"
        )

        sections.append("\n" + "="*47)
        sections.append("---- DETAILED RESULTS (DEDUPLICATED PER HOST) ----")
        sections.append("="*47 + "\n")

        # One block per HOST (not per command), merging -sS/-sV/-sn data
        for ip in discovered:

            host = structured_hosts.get(ip)
            tags = asset_tags.get(ip, [])
            vulns = vulnerabilities.get(ip, [])

            if host is None:
                sections.append(f">>> HOST: {ip} <<<")
                sections.append("No structured data available for this host.\n")
                continue

            sections.append(f">>> HOST: {host.ip_address} <<<")
            sections.append(f"Status      : {host.status.value}")
            sections.append(f"MAC Address : {host.mac_address or 'Unknown'}")
            sections.append(f"Vendor      : {host.vendor or 'Unknown'}")
            
            # Affichage des Tags découverts (Phase 5)
            sections.append(f"Discovered Tags : {', '.join(tags) if tags else 'None'}")

            if host.ports:
                sections.append(f"Open Ports  : {len(host.ports)}")
                for port in sorted(host.ports, key=lambda p: p.port):
                    service = port.service or "unknown"
                    version = f" ({port.version})" if port.version else ""
                    sections.append(
                        f"  - {port.port}/{port.protocol} {port.state} "
                        f"{service}{version}"
                    )
            else:
                sections.append("Open Ports  : None detected")

            # Affichage des Recommandations & Risques (Phase 6)
            if vulns:
                sections.append("\n  Security Recommendations & Risk Analysis:")
                for rec in vulns:
                    sections.append(f"    * {rec}")

            sections.append("\n" + "="*47 + "\n")

        final_summary = "\n".join(sections)

        synthetic_command = CommandInfo(
            command="OddNet Multi-Stage Pipeline",
            objective="Consolidated Discovery and Enumeration",
            description="Final aggregation of all executed steps.",
            arguments=[],
            risk_level=RiskLevel.LOW,
            impact="Global Network Mapping",
            estimated_duration="Completed",
            justification="Automated pipeline termination."
        )

        synthetic_validation = ValidationInfo(
            action="Approve",
            comments="Auto-generated synthesis report."
        )

        state["report"] = ReportInfo(
            audit=audit,
            network_information=network,
            approved_command=synthetic_command,
            validation=synthetic_validation,
            execution_output=final_summary
        )

        return state