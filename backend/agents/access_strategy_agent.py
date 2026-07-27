"""
Access Strategy Agent.

Pure data-processing step (no LLM, no guardrail, no human
validation): for each structured host discovered during enumeration,
looks up the static credential store entry (username, credential_id)
and combines it with the dynamically discovered SSH port (from
Nmap's -sV port scan results) to build an AccessStrategy.

Hosts not present in the credential store, or with no SSH service
detected, are simply skipped (no access strategy generated).
"""

from backend.models.state import AuditState
from backend.tools.credential_store import CredentialStore


class AccessStrategyAgent:

    @staticmethod
    def run(state: AuditState) -> AuditState:

        print("\n[Access Strategy Agent] Building SSH access strategies...\n")

        structured_hosts = state.get("structured_hosts", {})

        if "access_strategies" not in state:
            state["access_strategies"] = {}

        for ip, host_result in structured_hosts.items():

            strategy = CredentialStore.build_access_strategy(ip, host_result)

            if strategy is not None:
                state["access_strategies"][ip] = strategy
                # Afin de respecter le modèle Pydantic, on accède aux attributs
                print(
                    f"  {ip} -> SSH access strategy: "
                    f"{strategy.username}@{ip}:{strategy.port} "
                    f"(credential_id={strategy.credential_id})"
                )
            else:
                print(f"  {ip} -> no access strategy (not in store or no SSH found)")

        print(
            f"\n[Access Strategy Agent] "
            f"{len(state['access_strategies'])} strategy(ies) generated.\n"
        )

        # CORRECTION : Passer au stage identity_collection (Phase 3)
        # au lieu de terminer prématurément le workflow avec "done"
        state["stage"] = "identity_collection"

        # CORRECTION : current_host_index pointe après la fin de
        # discovered_hosts (boucle d'énumération terminée) — on le
        # réinitialise pour que l'Identity Agent reparte du premier host.
        state["current_host_index"] = 0
        state["current_command_index"] = 0
        state["current_command"] = None
        state["guardrail_status"] = None
        state["validation"] = None

        return state