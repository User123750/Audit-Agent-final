"""
Identity Collection Agent (Phase 3).

Only hosts with a resolved SSH access_strategy (built during Phase 2 by
AccessStrategyAgent) are eligible for identity collection. This node's
job is purely about ADVANCING the host loop:

  1. Starting at current_host_index, find the next host in
     discovered_hosts that has an entry in access_strategies.
  2. If found: set current_host_index to (that index + 1), and resolve
     the OS family already detected by Nmap (structured_hosts[ip].os_info)
     into state["detected_os_family"] so CommandAgent doesn't have to
     guess the OS from engineer feedback anymore.
  3. Delegate command generation to CommandAgent.run(state).
  4. If no eligible host remains, Phase 3 is over: move to stage
     "classification" (Phase 4) and leave current_command as None.
"""

from backend.models.state import AuditState
from backend.agents.command_agent import CommandAgent
from backend.utils.os_detect import detect_os_family


class IdentityAgent:

    @staticmethod
    def run(state: AuditState) -> AuditState:

        discovered_hosts = state.get("discovered_hosts", [])
        access_strategies = state.get("access_strategies", {})
        host_idx = state.get("current_host_index", 0)

        # Cherche le prochain host éligible (qui a un accès SSH résolu)
        while host_idx < len(discovered_hosts):
            candidate_ip = discovered_hosts[host_idx]
            if candidate_ip in access_strategies:
                break
            host_idx += 1
        else:
            # Aucun host éligible restant -> Phase 3 terminée
            print("\n[Identity Agent] Plus aucun host éligible SSH. Passage à la Phase 4 (Classification).\n")
            state["stage"] = "classification"
            state["current_command"] = None
            return state

        target_ip = discovered_hosts[host_idx]
        strategy = access_strategies[target_ip]

        # OS déjà détecté par Nmap (-O / -sV) pendant l'énumération —
        # on le résout ici une fois, CommandAgent l'utilisera directement.
        structured_hosts = state.get("structured_hosts", {})
        host_result = structured_hosts.get(target_ip)
        os_info = host_result.os_info if host_result is not None else None
        os_family = detect_os_family(os_info)
        state["detected_os_family"] = os_family

        print(
            f"\n[Identity Agent] Host cible : {target_ip} "
            f"(SSH {strategy.username}@{target_ip}:{strategy.port}) "
            f"— OS détecté : {os_family} (os_info='{os_info}')\n"
        )

        # Convention : on avance l'index AVANT de générer la commande, pour
        # que CommandAgent et get_current_key retrouvent le host courant via
        # (current_host_index - 1).
        state["current_host_index"] = host_idx + 1

        # Délègue la génération de la commande SSH au Command Agent
        # (branche stage == "identity_collection" déjà présente dedans).
        return CommandAgent.run(state)