"""
Human validation node (HITL).
Displays the full proposed command to the engineer BEFORE any menu
(command, objective, description, arguments, risk_level, impact,
estimated_duration, justification), then asks for a decision:
Approve / Reject / Modify.
Batch approval (bug fix #10): the FIRST time this node runs during the
"enumeration" stage, it additionally asks whether to auto-approve all
remaining enumeration scans. This only applies to stage == "enumeration".
"""

from backend.models.state import AuditState
from backend.models.validation import ValidationInfo, ValidationAction
from backend.api import hitl_bridge


def _command_to_payload(command_info) -> dict:
    return {
        "command": command_info.command,
        "objective": command_info.objective,
        "description": command_info.description,
        "arguments": [
            {"argument": a.argument, "explanation": a.explanation}
            for a in command_info.arguments
        ],
        "risk_level": command_info.risk_level.value,
        "impact": command_info.impact,
        "estimated_duration": command_info.estimated_duration,
        "justification": command_info.justification,
    }


def _print_command(command_info) -> None:
    print("\n" + "=" * 60)
    print("COMMANDE PROPOSÉE - VALIDATION REQUISE")
    print("=" * 60)
    print(f"Commande            : {command_info.command}")
    print(f"Objectif            : {command_info.objective}")
    print(f"Description         : {command_info.description}")
    if command_info.arguments:
        print("Arguments           :")
        for arg in command_info.arguments:
            print(f"  - {arg.argument} : {arg.explanation}")
    print(f"Niveau de risque    : {command_info.risk_level.value}")
    print(f"Impact              : {command_info.impact}")
    print(f"Durée estimée       : {command_info.estimated_duration}")
    print(f"Justification       : {command_info.justification}")
    print("-" * 60)


def human_validation_node(state: AuditState) -> AuditState:

    command_info = state["current_command"]
    audit_id = state.get("audit_id")

    # --- Mode API (frontend React) : pas d'input(), on passe par le pont HITL ---
    if audit_id is not None:
        result = hitl_bridge.request_validation(
            audit_id, _command_to_payload(command_info)
        )
        state["validation"] = ValidationInfo(
            action=ValidationAction(result["action"]),
            comments=result.get("comments"),
        )
        if result["action"] == "Approve" and state.get("stage") == "enumeration":
            state.setdefault("batch_approved", False)
        return state

    # --- Mode CLI (inchangé) ---
    _print_command(command_info)

    stage = state.get("stage")

    # --- Batch approval (Bug #10) : uniquement en phase "enumeration" ---
    if stage == "enumeration":

        if state.get("batch_approved"):
            print("[Auto-approuvé — batch enumeration activé]")
            state["validation"] = ValidationInfo(action=ValidationAction.APPROVE)
            return state

        if state.get("batch_approved") is None:
            answer = input(
                "Approuver automatiquement tous les scans d'énumération "
                "restants ? (y/n) : "
            ).strip().lower()
            state["batch_approved"] = (answer == "y")

            if state["batch_approved"]:
                state["validation"] = ValidationInfo(action=ValidationAction.APPROVE)
                return state

    # --- Menu standard ---
    choice = input("1) Approve  2) Reject  3) Modify\nVotre choix : ").strip()

    if choice == "1":
        state["validation"] = ValidationInfo(action=ValidationAction.APPROVE)
    elif choice == "2":
        state["validation"] = ValidationInfo(action=ValidationAction.REJECT)
    elif choice == "3":
        comments = input("Quelle modification voulez-vous demander ? : ")
        state["validation"] = ValidationInfo(
            action=ValidationAction.MODIFY, comments=comments
        )
    else:
        print("Choix invalide — commande rejetée par défaut.")
        state["validation"] = ValidationInfo(action=ValidationAction.REJECT)

    return state