"""
Guardrail node.

Thin LangGraph node wrapping CommandValidator: reads the currently
proposed command and the audit stage from the state, validates it,
and writes the result back into guardrail_status ("Approved" /
"Blocked") so the Supervisor can decide the next step.
"""

from backend.models.state import AuditState
from backend.guardrails.command_validator import CommandValidator


def guardrail_node(state: AuditState) -> AuditState:

    command_info = state.get("current_command")

    if command_info is None:
        state["guardrail_status"] = "Blocked"
        return state

    stage = state.get("stage")
    is_valid, reason = CommandValidator.validate(command_info.command, stage=stage)

    if is_valid:
        state["guardrail_status"] = "Approved"
        print(f"\n[Guardrail] Commande validée : {command_info.command}\n")
    else:
        state["guardrail_status"] = "Blocked"
        print(f"\n[Guardrail] Commande BLOQUÉE : {reason}\n")

    return state