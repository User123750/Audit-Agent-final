"""
OddNet API — couche minimale pour connecter le frontend React.

Lancement : uvicorn backend.api.main:app --reload --port 8000

Ne touche pas à la logique des agents : lance simplement graph.invoke()
dans un thread, avec state["audit_id"] renseigné pour que
human_validation_agent.py sache qu'il doit passer par le pont HITL
(backend/api/hitl_bridge.py) au lieu d'un input().
"""

import threading
import uuid

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend import config  # charge le .env (voir fix appliqué dans test_workflow.py)
from backend.models.audit import AuditInfo, AuditStatus
from backend.models.state import AuditState, DEFAULT_ENUMERATION_COMMANDS
from backend.api import hitl_bridge
from core_langgraph.graph import graph


app = FastAPI(title="OddNet API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # basique — à restreindre en prod
    allow_methods=["*"],
    allow_headers=["*"],
)


class NewAuditRequest(BaseModel):
    company: str
    engineer: str
    objective: str


class ValidationRequest(BaseModel):
    action: str  # "Approve" | "Reject" | "Modify"
    comments: str | None = None


def _run_graph_in_background(audit_id: str, audit: AuditInfo) -> None:
    session = hitl_bridge.get_session(audit_id)

    state: AuditState = {
        "audit": audit,
        "network_info": None,
        "command_history": [],
        "current_command": None,
        "guardrail_status": None,
        "validation": None,
        "execution_output": None,
        "report": None,
        "stage": "discovery",
        "discovered_hosts": [],
        "current_host_index": 0,
        "current_command_index": 0,
        "commands_per_host": DEFAULT_ENUMERATION_COMMANDS,
        "host_results": {},
        "partial_reports": {},
        "structured_hosts": {},
        "access_strategies": {},
        "classifications": {},
        "asset_tags": {},
        "vulnerabilities": {},
        "batch_approved": None,
        "audit_id": audit_id,  # clé lue par human_validation_agent.py
    }

    try:
        result = graph.invoke(state, config={"recursion_limit": 500})
        session.report = result.get("report")
    except Exception as exc:  # basique : on remonte l'erreur au frontend
        session.error = str(exc)
    finally:
        session.done = True
        session.stage = "done"


@app.post("/audits")
def create_audit(req: NewAuditRequest):
    audit_id = str(uuid.uuid4())
    audit = AuditInfo(company=req.company, engineer=req.engineer, objective=req.objective)
    audit.status = AuditStatus.IN_PROGRESS

    hitl_bridge.create_session(audit_id)

    thread = threading.Thread(
        target=_run_graph_in_background, args=(audit_id, audit), daemon=True
    )
    thread.start()

    return {"audit_id": audit_id}


@app.get("/audits/{audit_id}")
def get_audit_status(audit_id: str):
    session = hitl_bridge.get_session(audit_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Audit introuvable")

    return {
        "audit_id": audit_id,
        "done": session.done,
        "report": session.report,
        "error": session.error,
        "pending_command": session.pending_command,
        "trace": session.trace,
    }


@app.post("/audits/{audit_id}/validate")
def validate_command(audit_id: str, req: ValidationRequest):
    if req.action not in ("Approve", "Reject", "Modify"):
        raise HTTPException(status_code=400, detail="action invalide")

    ok = hitl_bridge.submit_validation(audit_id, req.action, req.comments)
    if not ok:
        raise HTTPException(
            status_code=409, detail="Aucune commande en attente de validation"
        )

    return {"ok": True}