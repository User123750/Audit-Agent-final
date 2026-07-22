"""
Shared LangGraph state.
"""

from typing import Annotated, Optional, TypedDict

from backend.models.audit import AuditInfo
from backend.models.command import CommandInfo
from backend.models.report import ReportInfo
from backend.models.validation import ValidationInfo
from backend.models.host import HostResult
from backend.models.access_strategy import AccessStrategy


# Politique d'énumération par défaut : 3 commandes par host découvert.
DEFAULT_ENUMERATION_COMMANDS = ["-sS", "-sV", "-sn"]


def merge_dict(existing: Optional[dict], new: Optional[dict]) -> dict:
    """
    Reducer: fusionne les nouvelles paires clé/valeur dans le dictionnaire existant.
    Gère les états initiaux (None) pour éviter les crashs au démarrage du graphe.
    """
    if existing is None:
        existing = {}
    if new is None:
        return existing
    return {**existing, **new}


def get_current_key(state: dict) -> str:
    """
    Détermine la clé courante pour stocker les résultats et rapports partiels.
    """
    stage = state.get("stage", "discovery")

    if stage == "discovery":
        return "discovery"
        
    # Gestion intelligente de l'index pour la Phase d'identité
    if stage == "identity_collection":
        discovered = state.get("discovered_hosts", [])
        host_idx = state.get("current_host_index", 0)
        
        # L'IdentityAgent incrémente l'index AVANT l'exécution et le rapport.
        if state.get("current_command") is not None:
            host_idx -= 1
            
        if not discovered or host_idx < 0 or host_idx >= len(discovered):
            return "unknown_target"
        return discovered[host_idx]

    # En phase d'énumération, on retourne host + commande courante
    discovered = state.get("discovered_hosts", [])
    host_idx = state.get("current_host_index", 0)
    cmd_idx = state.get("current_command_index", 0)
    commands_per_host = state.get("commands_per_host", DEFAULT_ENUMERATION_COMMANDS)

    if not discovered or host_idx >= len(discovered):
        return "unknown_target"

    host = discovered[host_idx]

    if cmd_idx >= len(commands_per_host):
        return f"{host}_unknown_command"

    flag = commands_per_host[cmd_idx]

    return f"{host}_{flag}"


class NetworkInfo(TypedDict):
    """
    Network information collected by the Network Agent.
    """
    ip_address: str
    subnet_mask: str
    gateway: str


class AuditState(TypedDict):
    """
    Shared state exchanged between all agents.
    """
    # Audit global info
    audit: AuditInfo

    # Network discovery
    network_info: Optional[NetworkInfo]

    # Previously proposed commands
    command_history: Annotated[list[str], "append"]

    # Current command
    current_command: Optional[CommandInfo]

    # Guardrail result
    guardrail_status: Optional[str]

    # Engineer validation
    validation: Optional[ValidationInfo]

    # Execution output
    execution_output: Optional[str]

    # Final report
    report: Optional[ReportInfo]

    # --- Pipeline discovery -> enumeration -> access_strategy -> identity_collection -> classification -> done ---

    # Contrôle du flux de l'audit
    stage: str  # "discovery" | "enumeration" | "access_strategy" | "identity_collection" | "classification" | "done"

    # Liste des cibles identifiées lors de la phase discovery
    discovered_hosts: list[str]

    # Pointeur pour la boucle d'énumération (quel host)
    current_host_index: int

    # Pointeur pour la boucle de commandes au sein d'un host
    current_command_index: int

    # Liste des commandes à exécuter pour CHAQUE host découvert
    commands_per_host: list[str]

    # Accumulateur des résultats bruts par clé (host_flag)
    host_results: Annotated[dict[str, str], merge_dict]

    # Accumulateur des rapports structurés par étape/host_flag
    partial_reports: Annotated[dict[str, ReportInfo], merge_dict]

    # Accumulateur des résultats STRUCTURÉS par host (IP)
    structured_hosts: Annotated[dict[str, HostResult], merge_dict]

    # Stratégies d'accès SSH générées pour les hosts éligibles
    access_strategies: Annotated[dict[str, AccessStrategy], merge_dict]
    
    # NOUVEAU (Phase 4): Dictionnaire pour stocker la classe finale de chaque IP (ex: "Linux Endpoint")
    classifications: Annotated[dict[str, str], merge_dict]
    # NOUVEAU (Phase 5): Dictionnaire pour stocker les tags dynamiques par IP
    asset_tags: Annotated[dict[str, list[str]], merge_dict]
    # Auto-approbation par lots
    batch_approved: Optional[bool]