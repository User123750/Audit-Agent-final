import datetime
import logging
import subprocess
import re
from backend.agents.identity_agent import IdentityCollectionAgent

logger = logging.getLogger("OddNet.Workflow")

class Workflow:
    @staticmethod
    def run(state: dict) -> dict:
        """
        Exécute le pipeline réel d'audit : Nmap (Scan + OS Fingerprinting) -> Identity Agent -> Analyse -> Rapport.
        """
        logger.info("=== DÉMARRAGE DU WORKFLOW RÉEL ODDNET ===")
        
        target = state.get("target_network", "127.0.0.1")
        print(f"\n[*] [1/4] Lancement du vrai scan Nmap sur la cible : {target}...")
        
        # Commande Nmap réelle (-sV pour les services, -O pour l'OS)
        # Note: Nécessite les privilèges admin/root pour -O
        nmap_cmd = f"nmap -sV -O {target}"
        
        hosts_data = {}
        raw_output = ""
        
        try:
            result = subprocess.run(nmap_cmd, shell=True, capture_output=True, text=True, timeout=120)
            raw_output = result.stdout
            print("[*] Scan Nmap terminé avec succès. Analyse du résultat...")
        except Exception as e:
            print(f"[-] Erreur critique lors de l'exécution de Nmap : {e}")
            raw_output = f"Erreur d'exécution : {e}"

        # --- PARSING DES RÉSULTATS NMAP ---
        os_info = "Système inconnu (Privilèges root requis pour -O)"
        for line in raw_output.splitlines():
            if "OS details:" in line or "Running:" in line:
                os_info = line.split(":", 1)[1].strip()
                break

        ports = []
        for line in raw_output.splitlines():
            if "/tcp" in line and "open" in line:
                parts = line.split()
                if len(parts) >= 2:
                    port_proto = parts[0].split("/")
                    service = parts[1]
                    version = " ".join(parts[2:]) if len(parts) > 2 else ""
                    ports.append({
                        "port": int(port_proto[0]),
                        "protocol": port_proto[1],
                        "service": service,
                        "version": version
                    })

        # Tags automatiques basés sur les services détectés et l'OS
        detected_tags = [os_info.lower()]
        for p in ports:
            detected_tags.append(p["service"].lower())

        hosts_data[target] = {
            "status": "up",
            "mac_address": "Locale / Directe",
            "vendor": "Local Host",
            "tags": detected_tags,
            "os_info": os_info,
            "ports": ports,
            "raw_output": raw_output
        }
        
        state["hosts_data"] = hosts_data
        
        # --- [2/4] IDENTITY AGENT (Génération dynamique) ---
        print("[*] [2/4] Exécution de l'Identity Agent (Commandes dynamiques)...")
        agent = IdentityCollectionAgent()
        
        for ip, host_info in state["hosts_data"].items():
            cmd = agent.generate_command(ip, host_info)
            print(f" -> Cible {ip} | OS : {host_info.get('os_info')} | Commande générée : {cmd}")
            host_info["identity_command_executed"] = cmd
            
        # --- [3/4] ANALYSE DES RISQUES ---
        print("[*] [3/4] Analyse des risques et génération des recommandations...")
        vulnerabilities = {}
        for ip, host_info in state["hosts_data"].items():
            recs = []
            host_ports = host_info.get("ports", [])
            
            for p in host_ports:
                if p["service"] == "ssh":
                    recs.append(f"Vérifier la configuration du service SSH (Port {p['port']}) et désactiver l'accès root par mot de passe.")
                elif p["service"] in ["http", "https"]:
                    recs.append(f"S'assurer que le serveur web (Port {p['port']}) utilise des certificats SSL/TLS valides et est à jour.")
            
            if not recs:
                recs.append("Aucun service critique exposé détecté sur les ports scannés.")
                
            vulnerabilities[ip] = recs
            
        state["vulnerabilities_data"] = vulnerabilities
        
        # --- [4/4] COMPILATION DU RAPPORT ---
        print("[*] [4/4] Compilation du rapport final structuré...")
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        report = "=" * 60 + "\n"
        report += "          RAPPORT D'AUDIT RÉEL - ODDNET AI          \n"
        report += "=" * 60 + "\n\n"
        
        report += "### 1. SYNTHÈSE DE LA DÉCOUVERTE & PÉRIMÈTRE\n"
        report += f"• Date et Heure de l'audit : {timestamp}\n"
        report += f"• Cible Scannée            : {target}\n"
        report += f"• Mode d'exécution         : Réel (Nmap Local Subprocess)\n\n"
        report += "-" * 60 + "\n\n"

        report += "### 2. INVENTAIRE TECHNIQUE & EMPREINTE OS\n\n"
        for ip, data in state.get("hosts_data", {}).items():
            report += f"> HÔTE : {ip}\n"
            report += f"  - Statut         : {data.get('status', 'up').upper()}\n"
            report += f"  - Empreinte OS   : {data.get('os_info', 'Inconnue')}\n"
            report += f"  - Commande ID    : {data.get('identity_command_executed', 'N/A')}\n"
            report += f"  - Ports Ouverts  : {len(data.get('ports', []))} port(s)\n"
            for p in data.get('ports', []):
                report += f"      * Port {p['port']}/{p['protocol']} -> {p['service']} ({p['version']})\n"
            report += "\n"
            
        report += "-" * 60 + "\n\n"

        report += "### 3. ANALYSE DES RISQUES & RECOMMANDATIONS\n\n"
        for ip, recs in state.get("vulnerabilities_data", {}).items():
            report += f">> ANALYSE DE SÉCURITÉ POUR LA MACHINE : {ip}\n"
            for idx, rec in enumerate(recs, 1):
                report += f"  {idx}. [RECOMMANDATION] {rec}\n"
            report += "\n"

        report += "=" * 60 + "\n"
        report += "              FIN DU RAPPORT - ODDNET AI               \n"
        report += "=" * 60 + "\n"

        state["final_report"] = report
        state["stage"] = "done"
        return state