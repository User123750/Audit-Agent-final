from backend.models.state import AuditState
from backend.models.command import CommandInfo, RiskLevel

class IdentityCollectionAgent:
    
    @staticmethod
    def run(state: AuditState):
        print("\n[Identity Collection Agent] Préparation des commandes d'identification OS (Phase 3)...")
        
        strategies = state.get("access_strategies", {})
        discovered = state.get("discovered_hosts", [])
        host_idx = state.get("current_host_index", 0)
        
        # 1. Vérification si tous les hôtes ont été parcourus
        if host_idx >= len(discovered):
            print("[Identity Agent] Tous les hôtes ont été parcourus. Fin de la phase d'identité. Passage à la classification.")
            # NOUVEAU ROUTAGE: On passe à la Phase 4 (Classification) au lieu de 'done'
            state["stage"] = "classification"
            state["current_command"] = None
            return state
            
        target_ip = discovered[host_idx]
        strategy = strategies.get(target_ip)
        
        print(f"[Identity Agent] Analyse de l'hôte {target_ip} (Index: {host_idx + 1}/{len(discovered)})")
        
        # On vérifie juste si la stratégie existe. 
        # Le Pydantic AccessStrategy n'a pas d'attributs 'status' ou 'method'.
        if strategy:
            print(f"[Identity Agent] Accès SSH prêt pour {target_ip} (Credential ID: {strategy.credential_id}). Génération de la commande...")
            
            # Commande dynamique basée sur les données factuelles de Nmap (-sV)
            bash_command = "cat /etc/os-release"  # Défaut Linux
            
            structured_hosts = state.get("structured_hosts", {})
            host_info = structured_hosts.get(target_ip)
            
            if host_info and host_info.os_info:
                os_lower = host_info.os_info.lower()
                if "windows" in os_lower:
                    bash_command = "systeminfo"
            
            state["current_command"] = CommandInfo(
                command=bash_command,
                objective="Déterminer la famille, distribution et version de l'OS (Phase 3)",
                description="Exécution de la commande système via SSH sécurisé",
                arguments=[],
                risk_level=RiskLevel.LOW,
                impact="Lecture seule des informations système",
                estimated_duration="Quelques secondes",
                justification="Phase 3: Identity Collection & System Identification"
            )
            print(f"[Identity Agent] Commande générée pour {target_ip} : {bash_command}")
            
            state["stage"] = "identity_collection"
            state["current_host_index"] = host_idx + 1
            
        else:
            print(f"[Identity Agent] Pas d'accès SSH valide pour {target_ip}. Passage au suivant.")
            state["current_command"] = None
            state["current_host_index"] = host_idx + 1
            
            # Vérification après incrémentation
            if state["current_host_index"] >= len(discovered):
                print("[Identity Agent] Fin de la liste des hôtes. Passage au stage 'classification'.")
                # NOUVEAU ROUTAGE: On passe à la Phase 4 (Classification) au lieu de 'done'
                state["stage"] = "classification"
            
        return state