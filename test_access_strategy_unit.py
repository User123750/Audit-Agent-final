import os
import json
from backend.models.host import HostResult, PortInfo
from backend.agents.access_strategy_agent import AccessStrategyAgent

# 1. Vérification/Création du fichier JSON de test pour être sûr que ça marche
CRED_PATH = "backend/config/credential_store.json"
os.makedirs(os.path.dirname(CRED_PATH), exist_ok=True)
with open(CRED_PATH, "w", encoding="utf-8") as f:
    json.dump({
        "192.168.3.10": {
            "username": "admin",
            "port": 0,
            "credential_id": "linux_prod_01"
        },
        "192.168.3.99": {
            "username": "root",
            "port": 0,
            "credential_id": "admin_cred_01"
        }
    }, f)

# 2. Création de "faux" résultats Nmap (Mocking)
# Scénario A : Hôte DANS le JSON, AVEC un port SSH (Même un port bizarre comme 2222)
host_a = HostResult(
    ip_address="192.168.3.10",
    status="up", # Remplace par ton Enum si tu utilises un Enum comme HostStatus.UP
    mac_address="AA:BB:CC:DD:EE:FF",
    vendor="TestVendor",
    os_info="Ubuntu",
    ports=[
        PortInfo(port=80, protocol="tcp", state="open", service="http", version="nginx"),
        PortInfo(port=2222, protocol="tcp", state="open", service="ssh", version="OpenSSH") # Port dynamique !
    ],
    raw_output=""
)

# Scénario B : Hôte DANS le JSON, mais AUCUN port SSH détecté par Nmap
host_b = HostResult(
    ip_address="192.168.3.99",
    status="up",
    mac_address="",
    vendor="",
    os_info="",
    ports=[
        PortInfo(port=80, protocol="tcp", state="open", service="http", version="Apache")
    ],
    raw_output=""
)

# Scénario C : Hôte avec SSH détecté, mais PAS DANS le JSON
host_c = HostResult(
    ip_address="192.168.3.50",
    status="up",
    mac_address="",
    vendor="",
    os_info="",
    ports=[
        PortInfo(port=22, protocol="tcp", state="open", service="ssh", version="OpenSSH")
    ],
    raw_output=""
)

# 3. Construction du State artificiel
state = {
    "structured_hosts": {
        "192.168.3.10": host_a,
        "192.168.3.99": host_b,
        "192.168.3.50": host_c
    },
    "access_strategies": {}
}

print("\n========== DÉBUT DU TEST UNITAIRE ==========\n")

# 4. Exécution directe de l'Agent
new_state = AccessStrategyAgent.run(state)

print("\n========== RÉSULTAT FINAL (state['access_strategies']) ==========\n")
for ip, strategy in new_state.get("access_strategies", {}).items():
    print(f"IP: {ip}")
    print(f"  -> Username      : {strategy.username}")
    print(f"  -> Port Dynamique: {strategy.port} (Doit être différent de 0 !)")
    print(f"  -> Credential ID : {strategy.credential_id}\n")

print(f"Le nouveau stage est passé à : '{new_state.get('stage')}'")