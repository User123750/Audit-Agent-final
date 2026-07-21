"""
Supervisor Agent.

Responsible for orchestrating the OddNet audit workflow.
The supervisor only decides the next node — it never mutates state.
All state mutations (resets, stage transitions, index increments)
happen in workflow.py, in the node branch that just executed.
"""

from backend.models.state import AuditState

class SupervisorAgent:

    @staticmethod
    def next_step(state: AuditState) -> str:
        """
        Decide which agent/node should execute next.
        """

        # ==========================================
        # 1. Network discovery
        # ==========================================
        if state.get("network_info") is None:
            return "network"

        # ==========================================
        # 2. Audit finished
        # ==========================================
        if state.get("stage") == "done":
            if state.get("report") is None:
                return "report"
            return "end"

        # ==========================================
        # 2b. Access strategy phase
        # ==========================================
        if state.get("stage") == "access_strategy":
            return "access_strategy"

        # ==========================================
        # 2c. Identity Collection phase (Phase 3 - NEW)
        # ==========================================
        if state.get("stage") == "identity_collection":
            # S'il n'y a pas encore de commande Bash générée, on va vers l'agent d'identité
            if state.get("current_command") is None:
                return "identity_collection"
            # Sinon, on laisse le flux descendre vers guardrail -> validation -> execution

        # ==========================================
        # 3. Command generation
        # ==========================================
        if state.get("current_command") is None:
            return "command"

        # ==========================================
        # 4. Guardrail validation
        # ==========================================
        if state.get("guardrail_status") is None:
            return "guardrail"

        if state.get("guardrail_status") == "Blocked":
            return "command"

        # ==========================================
        # 5. Human validation
        # ==========================================
        if state.get("validation") is None:
            return "human_validation"

        # ==========================================
        # 6. Engineer rejected / modified
        # ==========================================
        if state["validation"].action in ["Reject", "Modify"]:
            return "command"

        # ==========================================
        # 7. Execute command
        # ==========================================
        if (
            state["validation"].action == "Approve"
            and state.get("execution_output") is None
        ):
            return "execution"

        # ==========================================
        # 8. Partial report
        # ==========================================
        if state.get("stage") == "discovery":
            current_key = "discovery"

        elif state.get("stage") == "identity_collection":
            # Clé unique pour le rapport d'exécution Bash
            discovered = state.get("discovered_hosts", [])
            host_idx = state.get("current_host_index", 0)
            host = discovered[host_idx] if host_idx < len(discovered) else "unknown"
            current_key = f"{host}_identity"

        else:
            # stage == "enumeration"
            discovered = state.get("discovered_hosts", [])
            host_idx = state.get("current_host_index", 0)
            cmd_idx = state.get("current_command_index", 0)
            commands_per_host = state.get(
                "commands_per_host", ["-sS", "-sV", "-sn"]
            )

            if host_idx < len(discovered):
                host = discovered[host_idx]
                flag = (
                    commands_per_host[cmd_idx]
                    if cmd_idx < len(commands_per_host)
                    else "overflow"
                )
                current_key = f"{host}_{flag}"
            else:
                current_key = "overflow"

        reports = state.get("partial_reports", {})
        if current_key not in reports and current_key != "overflow":
            return "report"

        # ==========================================
        # 9. End (fallback safety net)
        # ==========================================
        return "end"