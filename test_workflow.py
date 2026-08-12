import logging

from backend import config  # charge le .env AVANT tout le reste (credentials SSH inclus)

from backend.models.audit import AuditInfo
from backend.models.state import AuditState, DEFAULT_ENUMERATION_COMMANDS
from core_langgraph.graph import graph

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("OddNet.TestWorkflow")

if __name__ == "__main__":
    print("=== DÉMARRAGE DU PIPELINE D'AUDIT RÉEL (ODDNET PFA) ===")

    audit = AuditInfo(
        company="Test",
        engineer="Rir",
        objective="Audit rapide de test isolé",
    )

    # ==========================================
    # MODE TEST CIBLÉ
    # ==========================================
    # Remplis cette liste avec les IP que tu veux tester (2, 3, ou plus).
    # Laisse-la vide ([]) pour revenir au comportement normal : discovery
    # sur tout le sous-réseau, puis enumeration sur tous les hosts trouvés.
    TEST_HOSTS = ["192.168.3.20", "192.168.3.10"]

    if TEST_HOSTS:
        print(f"[*] Mode test ciblé activé — hosts : {TEST_HOSTS}")
        print("[*] La phase 'discovery' (scan du sous-réseau entier) est sautée.\n")

    initial_state: AuditState = {
        "audit": audit,
        "network_info": None,
        "command_history": [],
        "current_command": None,
        "guardrail_status": None,
        "validation": None,
        "execution_output": None,
        "report": None,
        # Si TEST_HOSTS est rempli, on saute directement à "enumeration" avec
        # ces hosts déjà "découverts" — sinon comportement normal (discovery).
        "stage": "enumeration" if TEST_HOSTS else "discovery",
        "discovered_hosts": TEST_HOSTS if TEST_HOSTS else [],
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
    }

    print("\n[*] Lancement du graphe LangGraph (Exécution réelle)...")

    final_state = graph.invoke(initial_state, config={"recursion_limit": 500})

    # Affichage du rapport final lisible UNIQUEMENT (pas tout le state brut)
    print("\n" + final_state.get("report", "Aucun rapport généré."))