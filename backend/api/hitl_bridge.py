"""
HITL bridge.

Le graphe LangGraph tourne dans un thread à part (voir backend/api/main.py).
Quand human_validation_agent.py doit demander une validation à l'ingénieur,
il ne peut plus faire input() : il dépose la commande proposée ici et
attend (thread.Event) que l'API réponde via /audits/{id}/validate.

Un seul objet par audit_id, donc un seul audit "en attente de validation"
à la fois par id — suffisant pour un usage basique / un ingénieur.

Contient aussi la TRACE complète de l'audit (chaque commande + décision +
résultat), accumulée au fur et à mesure — pas seulement le rapport final.
"""

import threading
import time


class AuditSession:
    def __init__(self):
        self.pending_command: dict | None = None  # commande en attente d'affichage
        self.validation_result: dict | None = None  # réponse posée par l'API
        self.event = threading.Event()
        self.stage: str = "starting"
        self.report: str | None = None
        self.error: str | None = None
        self.done: bool = False
        self.trace: list[dict] = []  # historique complet, dans l'ordre chronologique


_sessions: dict[str, AuditSession] = {}
_lock = threading.Lock()


def create_session(audit_id: str) -> AuditSession:
    with _lock:
        session = AuditSession()
        _sessions[audit_id] = session
        return session


def get_session(audit_id: str) -> AuditSession | None:
    with _lock:
        return _sessions.get(audit_id)


def request_validation(audit_id: str, command_payload: dict) -> dict:
    """
    Appelé depuis human_validation_agent.py (thread du graphe).
    Bloque jusqu'à ce que l'API dépose une réponse via submit_validation().
    """
    session = get_session(audit_id)
    if session is None:
        raise RuntimeError(f"Session inconnue pour audit_id={audit_id}")

    session.pending_command = command_payload
    session.event.clear()
    session.event.wait()  # se réveille quand submit_validation() est appelé

    result = session.validation_result
    session.pending_command = None
    session.validation_result = None
    return result


def submit_validation(audit_id: str, action: str, comments: str | None) -> bool:
    """
    Appelé depuis la route POST /audits/{id}/validate (thread FastAPI).
    Débloque request_validation() ci-dessus.
    """
    session = get_session(audit_id)
    if session is None or session.pending_command is None:
        return False

    session.validation_result = {"action": action, "comments": comments}
    session.event.set()
    return True


def append_trace(
    audit_id: str,
    stage: str,
    command_payload: dict,
    validation: dict | None,
    output: str | None,
) -> None:
    """
    Ajoute une entrée à la trace complète de l'audit : commande proposée,
    décision de l'ingénieur, et résultat d'exécution. Appelé depuis
    execution_agent.py une fois l'exécution terminée.
    """
    session = get_session(audit_id)
    if session is None:
        return

    session.trace.append(
        {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "stage": stage,
            "command": command_payload,
            "validation": validation,
            "output": output,
        }
    )