import json
import os
from types import SimpleNamespace

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
        Katrje3 objet SimpleNamespace bach l'agent y9der ydir .username w .port bla mochkil.
        """
        creds = CredentialStore.get_credentials(ip_address)
        
        if creds:
            # SimpleNamespace kay7ewel le dict l'objet bach ykhedm m3a strategy.username
            return SimpleNamespace(
                method="SSH",
                status="READY",
                username=creds.get("username"),
                port=creds.get("port", 22), # 22 par défaut ila makanch f JSON
                credential_id=creds.get("credential_id")
            )
        else:
            return SimpleNamespace(
                method="UNKNOWN",
                status="MISSING_CREDENTIALS",
                username=None,
                port=None,
                credential_id=None
            )