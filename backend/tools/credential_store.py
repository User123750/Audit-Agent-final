import json
import os
from backend.models.access_strategy import AccessStrategy

class CredentialStore:
    
    @staticmethod
    def get_credentials(ip_address):
        """
        Kat9ra mn le fichier credential_store.json w katrje3 le dictionnaire dyal l'IP ciblée.
        """
        base_dir = os.path.dirname(os.path.abspath(__file__))
        json_path = os.path.join(base_dir, '..', 'config', 'credential_store.json')
        
        try:
            with open(json_path, 'r') as file:
                creds = json.load(file)
                return creds.get(ip_address)
        except FileNotFoundError:
            print(f"[Erreur] Le fichier {json_path} makaynch.")
            return None
        except json.JSONDecodeError:
            print(f"[Erreur] Le fichier {json_path} fih mochkil dyal formatage JSON.")
            return None

    @staticmethod
    def build_access_strategy(ip_address, host_result=None):
        """
        Kat-généri l'access strategy (Phase 2).
        CORRECTION BUG 1: Extrait le port SSH dynamiquement. 
        Si aucun port SSH n'est détecté, on skip l'host en retournant None.
        """
        creds = CredentialStore.get_credentials(ip_address)
        
        if not creds:
            return None
            
        ssh_port = 0
        
        # Extraction dynamique du port SSH depuis host_result (provenant de Nmap -sV)
        if host_result and hasattr(host_result, 'ports'):
            for port_info in host_result.ports:
                # Support pour la structure Pydantic ou Dict
                service = port_info.service if hasattr(port_info, 'service') else port_info.get('service', '')
                p_num = port_info.port if hasattr(port_info, 'port') else port_info.get('port', 0)
                
                if service and 'ssh' in service.lower():
                    ssh_port = p_num
                    break
                    
        # Règle stricte: S'il n'y a pas de port SSH ouvert, on ne génère PAS de stratégie
        if ssh_port == 0:
            return None
            
        # On retourne le vrai modèle Pydantic, pas un SimpleNamespace
        return AccessStrategy(
            ip_address=ip_address,
            username=creds.get("username"),
            port=ssh_port,
            credential_id=creds.get("credential_id")
        )