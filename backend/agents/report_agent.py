"""
Report Agent.

Universal 'report' node, called by the Supervisor after every executed
step of the pipeline (discovery, each enumeration scan, each identity
collection command) AND once at the very end (stage == "done").

Two responsibilities:

1. PARTIAL REPORT (stage != "done"):
   - Archives a short, human-readable summary of the step that just ran
     into partial_reports[current_key].
   - ADVANCES the state machine: increments current_command_index /
     current_host_index, transitions "stage" when a phase completes, and
     resets current_command / guardrail_status / validation /
     execution_output to None so the next step starts clean.
   Without this second part, the Supervisor would see the exact same
   current_key on its next decision and get stuck.

2. FINAL REPORT (stage == "done" and report is None):
   - Compiles the full, numbered, human-readable audit report from the
     REAL collected data: structured_hosts, access_strategies,
     classifications, asset_tags, vulnerabilities. No invented data.
"""

import datetime

from backend.models.state import AuditState, DEFAULT_ENUMERATION_COMMANDS


class ReportAgent:

    @staticmethod
    def run(state: AuditState) -> AuditState:

        if state.get("stage") == "done" and state.get("report") is None:
            state["report"] = ReportAgent._generate_final_report(state)
            return state

        ReportAgent._archive_partial_report(state)
        ReportAgent._advance(state)
        return state

    # ==========================================================
    # 1. PARTIAL REPORT + ADVANCE
    # ==========================================================

    @staticmethod
    def _current_key(state: AuditState) -> str:
        stage = state.get("stage")

        if stage == "discovery":
            return "discovery"

        if stage == "identity_collection":
            discovered = state.get("discovered_hosts", [])
            host_idx = state.get("current_host_index", 0) - 1
            host = discovered[host_idx] if 0 <= host_idx < len(discovered) else "unknown_target"
            return f"{host}_identity"

        # enumeration
        discovered = state.get("discovered_hosts", [])
        host_idx = state.get("current_host_index", 0)
        cmd_idx = state.get("current_command_index", 0)
        commands_per_host = state.get("commands_per_host", DEFAULT_ENUMERATION_COMMANDS)

        if not discovered or host_idx >= len(discovered):
            return "overflow"

        host = discovered[host_idx]
        flag = commands_per_host[cmd_idx] if cmd_idx < len(commands_per_host) else "overflow"
        return f"{host}_{flag}"

    @staticmethod
    def _archive_partial_report(state: AuditState) -> None:
        key = ReportAgent._current_key(state)

        if "partial_reports" not in state:
            state["partial_reports"] = {}

        command_info = state.get("current_command")
        validation = state.get("validation")
        output = state.get("execution_output", "")

        lines = [f">>> ÉTAPE : {key} <<<"]
        if command_info is not None:
            lines.append(f"Commande exécutée : {command_info.command}")
        if validation is not None:
            lines.append(f"Décision ingénieur : {validation.action.value}")
            if validation.comments:
                lines.append(f"Commentaire : {validation.comments}")
        lines.append(f"Résultat :\n{output}")

        state["partial_reports"][key] = "\n".join(lines)

    @staticmethod
    def _advance(state: AuditState) -> None:
        stage = state.get("stage")

        # Reset commun à chaque étape franchie
        state["current_command"] = None
        state["guardrail_status"] = None
        state["validation"] = None
        state["execution_output"] = None

        if stage == "discovery":
            state["stage"] = "enumeration"
            state["current_host_index"] = 0
            state["current_command_index"] = 0
            state["commands_per_host"] = state.get(
                "commands_per_host", DEFAULT_ENUMERATION_COMMANDS
            )
            return

        if stage == "identity_collection":
            # L'index a déjà été avancé par l'Identity Agent lui-même ;
            # rien à faire ici à part le reset commun ci-dessus.
            return

        # stage == "enumeration"
        discovered = state.get("discovered_hosts", [])
        commands_per_host = state.get("commands_per_host", DEFAULT_ENUMERATION_COMMANDS)

        cmd_idx = state.get("current_command_index", 0) + 1
        host_idx = state.get("current_host_index", 0)

        if cmd_idx >= len(commands_per_host):
            cmd_idx = 0
            host_idx += 1

        state["current_command_index"] = cmd_idx
        state["current_host_index"] = host_idx

        if host_idx >= len(discovered):
            state["stage"] = "access_strategy"

    # ==========================================================
    # 2. FINAL REPORT
    # ==========================================================

    @staticmethod
    def _generate_final_report(state: AuditState) -> str:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        audit = state.get("audit")
        network_info = state.get("network_info") or {}
        structured_hosts = state.get("structured_hosts", {})
        access_strategies = state.get("access_strategies", {})
        partial_reports = state.get("partial_reports", {})
        classifications = state.get("classifications", {})
        asset_tags = state.get("asset_tags", {})
        vulnerabilities = state.get("vulnerabilities", {})
        discovered_hosts = state.get("discovered_hosts", [])

        report = "=" * 60 + "\n"
        report += "          RAPPORT D'AUDIT DE SÉCURITÉ - ODDNET          \n"
        report += "=" * 60 + "\n\n"

        # --- 1. SYNTHÈSE ---
        report += "### 1. SYNTHÈSE DE LA DÉCOUVERTE & PÉRIMÈTRE\n"
        report += f"• Date et Heure de l'audit : {timestamp}\n"
        if audit is not None:
            report += f"• Entreprise               : {audit.company}\n"
            report += f"• Ingénieur                : {audit.engineer}\n"
            report += f"• Objectif de l'audit      : {audit.objective}\n"
        report += f"• Adresse IP locale        : {network_info.get('ip_address', 'Inconnue')}\n"
        report += f"• Passerelle (Gateway)     : {network_info.get('gateway', 'Inconnue')}\n"
        report += f"• Nombre d'hôtes découverts: {len(discovered_hosts)}\n\n"
        report += "-" * 60 + "\n\n"

        # --- 2. INVENTAIRE TECHNIQUE & EMPREINTE OS ---
        report += "### 2. INVENTAIRE TECHNIQUE & EMPREINTE OS\n\n"
        for ip in discovered_hosts:
            host = structured_hosts.get(ip)
            report += f"> HÔTE : {ip}\n"
            if host is not None:
                report += f"  - Statut         : {host.status.value.upper()}\n"
                report += f"  - Adresse MAC    : {host.mac_address or 'Inconnue'}\n"
                report += f"  - Vendor         : {host.vendor or 'Inconnu'}\n"
                if host.os_info:
                    if host.os_confidence is not None:
                        confidence_str = f" (confiance : {host.os_confidence}%)"
                    else:
                        confidence_str = " (confiance : N/A)"
                    os_line = f"{host.os_info}{confidence_str}"
                else:
                    os_line = "Inconnue"
                report += f"  - Empreinte OS   : {os_line}\n"
                report += f"  - Ports Ouverts  : {len(host.ports)} port(s)\n"
                for p in host.ports:
                    version = f" ({p.version})" if p.version else ""
                    report += f"      * Port {p.port}/{p.protocol} -> {p.service or 'inconnu'}{version}\n"
            else:
                report += "  - Aucune donnée structurée disponible.\n"
            report += "\n"
        report += "-" * 60 + "\n\n"

        # --- 3. ACCESS STRATEGY (Phase 2) ---
        report += "### 3. STRATÉGIE D'ACCÈS SSH\n\n"
        if access_strategies:
            for ip, strat in access_strategies.items():
                report += (
                    f"> {ip} -> {strat.username}@{ip}:{strat.port} "
                    f"(credential_id={strat.credential_id})\n"
                )
        else:
            report += "Aucun host éligible à un accès SSH (pas de credential ou pas de port SSH détecté).\n"
        report += "\n" + "-" * 60 + "\n\n"

        # --- 4. IDENTITY COLLECTION (Phase 3) ---
        report += "### 4. RÉSULTATS DE COLLECTE D'IDENTITÉ (SSH)\n\n"
        identity_keys = [k for k in partial_reports if k.endswith("_identity")]
        if identity_keys:
            for key in identity_keys:
                report += partial_reports[key] + "\n\n"
        else:
            report += "Aucune collecte d'identité effectuée (aucun host SSH éligible).\n\n"
        report += "-" * 60 + "\n\n"

        # --- 5. CLASSIFICATION & TAGS (Phases 4-5) ---
        report += "### 5. CLASSIFICATION DES ACTIFS\n\n"
        for ip in discovered_hosts:
            asset_class = classifications.get(ip, "Non classifié")
            tags = asset_tags.get(ip, [])
            report += f"> {ip} -> Classe : {asset_class} | Tags : {', '.join(tags) if tags else 'Aucun'}\n"
        report += "\n" + "-" * 60 + "\n\n"

        # --- 6. RÉSUMÉ EXÉCUTIF DES RISQUES ---
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for ip_data in vulnerabilities.values():
            risks_for_count = ip_data.get("risks", []) if isinstance(ip_data, dict) else []
            for risk in risks_for_count:
                sev = risk.get("severity", "Medium") if isinstance(risk, dict) else "Medium"
                if sev in severity_counts:
                    severity_counts[sev] += 1

        report += "### 6. RÉSUMÉ EXÉCUTIF DES RISQUES\n\n"
        report += (
            f"• Critiques : {severity_counts['Critical']}   "
            f"• Élevés : {severity_counts['High']}   "
            f"• Moyens : {severity_counts['Medium']}   "
            f"• Faibles : {severity_counts['Low']}\n\n"
        )
        report += "-" * 60 + "\n\n"

        # --- 7. ANALYSE DES RISQUES & RECOMMANDATIONS PAR MACHINE (Phase 6) ---
        report += "### 7. ANALYSE DES RISQUES & RECOMMANDATIONS PAR MACHINE\n\n"
        for ip in discovered_hosts:
            ip_data = vulnerabilities.get(ip, {})
            risks = ip_data.get("risks", []) if isinstance(ip_data, dict) else []
            recs = ip_data.get("recommendations", []) if isinstance(ip_data, dict) else (ip_data or [])

            report += f">> ANALYSE DE SÉCURITÉ POUR LA MACHINE : {ip}\n"

            if risks:
                report += "  Risques identifiés :\n"
                for idx, risk in enumerate(risks, 1):
                    severity = risk.get("severity", "Medium") if isinstance(risk, dict) else "Medium"
                    description = risk.get("description", "") if isinstance(risk, dict) else str(risk)
                    report += f"    {idx}. [{severity.upper()}] {description}\n"
            else:
                report += "  Risques identifiés : aucun constat justifiable à partir des données collectées.\n"

            if recs:
                report += "  Recommandations :\n"
                for idx, rec in enumerate(recs, 1):
                    report += f"    {idx}. {rec}\n"
            else:
                report += "  Recommandations : aucune.\n"

            report += "\n"

        report += "=" * 60 + "\n"
        report += "              FIN DU RAPPORT - ODDNET AI               \n"
        report += "=" * 60 + "\n"

        return report