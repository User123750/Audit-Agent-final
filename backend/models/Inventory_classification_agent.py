"""
Inventory Classification Agent.

S'exécute juste après discovery (-sn) et avant l'enumeration lourde.
Pour chaque host découvert, lance un scan léger (run_nmap_inventory_scan)
et classifie le type d'appareil par règles simples sur les ports/services
trouvés — pas d'appel LLM ici, c'est rapide et déterministe.
"""

import re

from backend.models.state import AuditState
from backend.tools.nmap_tools import build_command
from backend.tools.nmap_tool import NmapTool  # exécution subprocess (liste d'args)


# Règles port -> type d'appareil. Vérifiées dans l'ordre ; la première
# règle qui matche gagne.
CLASSIFICATION_RULES = [
    ({9100, 631}, "printer"),
    ({3389}, "windows_workstation_or_server"),
    ({445, 139}, "windows_host"),
    ({22}, "linux_host"),
    ({80, 443}, "web_or_router_device"),
]


def _extract_open_ports(nmap_output: str) -> set[int]:
    """Parse basique de la sortie nmap pour en extraire les ports 'open'."""
    ports = set()
    for line in nmap_output.splitlines():
        match = re.match(r"^(\d+)/tcp\s+open", line.strip())
        if match:
            ports.add(int(match.group(1)))
    return ports


def _classify_from_ports(open_ports: set[int]) -> str:
    for rule_ports, label in CLASSIFICATION_RULES:
        if open_ports & rule_ports:
            return label
    return "unknown_device"


class InventoryClassificationAgent:

    @classmethod
    def run(cls, state: AuditState) -> AuditState:
        discovered_hosts = state.get("discovered_hosts", [])
        classifications = dict(state.get("inventory_classifications") or {})

        for target in discovered_hosts:
            if target in classifications:
                continue  # déjà classifié (reprise après crash/pause)

            args = build_command("run_nmap_inventory_scan", {"target": target})
            output = NmapTool.run(args)

            open_ports = _extract_open_ports(output)
            classifications[target] = _classify_from_ports(open_ports)

        state["inventory_classifications"] = classifications
        state["stage"] = "enumeration"

        return state