"""
Execution Agent.

Responsible for executing approved audit commands, archiving raw
output per stage/host, parsing discovery hosts, and — during
enumeration — merging structured per-scan results (HostResult) into
a single deduplicated record per IP for the final report.
"""

import re
import subprocess
import paramiko  # Ajout de Paramiko pour le support SSH

from backend.models.state import AuditState, get_current_key
from backend.models.validation import ValidationAction
from backend.models.host import HostResult
from backend.tools.nmap_parser import NmapParser
from backend.tools.credential_store import CredentialStore

class ExecutionAgent:

    _NMAP_HOST_PATTERN = re.compile(
        r"Nmap scan report for (?:\S+ \()?(\d{1,3}(?:\.\d{1,3}){3})\)?"
    )

    _FINGERPRINT_BLOCK_PATTERN = re.compile(
        r"==+NEXT SERVICE FINGERPRINT.*?(?=\n\n|\Z)",
        re.DOTALL
    )

    @staticmethod
    def run(state: AuditState):

        print("\n[Execution Agent] Starting execution...\n")

        # ==========================================
        # Check command exists & Engineer approval
        # ==========================================
        command_info = state.get("current_command")
        if command_info is None:
            state["execution_output"] = "Execution failed: no command found."
            return state

        validation = state.get("validation")
        if validation is None or validation.action != ValidationAction.APPROVE:
            state["execution_output"] = "Execution blocked: command not approved."
            return state

        command = command_info.command
        print(f"Executing: {command}\n")

        try:
            # ==========================================
            # ROUTAGE : Nmap (Local) vs Bash (SSH Distant)
            # ==========================================
            if command.startswith("nmap") or command.startswith("arp-scan"):
                # Exécution NMAP locale via subprocess
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    encoding="cp850",
                    errors="replace",
                    timeout=300
                )
                output = result.stdout
                if result.stderr:
                    output += "\n\nErrors:\n" + result.stderr
                # Nettoyage spécifique Nmap
                output = ExecutionAgent._strip_fingerprints(output)
            else:
                # Exécution Bash via SSH (Module 5)
                target_ip = get_current_key(state)
                
                # Récupération dynamique depuis le fichier JSON
                credentials = CredentialStore.get_credentials(target_ip)
                
                if credentials:
                    username = credentials.get("username")
                    cred_id = credentials.get("credential_id")
                    
                    print(f"[Execution Agent] Authentification trouvée pour {target_ip} (Credential ID: {cred_id}).")
                    
                    # SIMULATION D'UN VAULT SÉCURISÉ
                    # En production, ce dictionnaire doit être remplacé par un vrai gestionnaire de secrets
                    mock_vault = {
                        "linux_prod_01": "Password123!",
                        "admin_cred_01": "SuperSecretRootPwd!"
                    }
                    
                    actual_password = mock_vault.get(cred_id)
                    
                    if actual_password:
                        output = ExecutionAgent._run_ssh_command(
                            ip=target_ip,
                            username=username, 
                            password=actual_password,
                            command=command
                        )
                    else:
                        output = f"Execution blocked: Le mot de passe pour le credential_id '{cred_id}' est introuvable dans le Vault."
                        print(output)
                else:
                    output = f"Execution blocked: Aucun credential trouvé pour l'IP {target_ip} dans le store."
                    print(output)

            state["execution_output"] = output

            # ==========================================
            # Archive raw output
            # ==========================================
            key = get_current_key(state)
            if "host_results" not in state:
                state["host_results"] = {}
            state["host_results"][key] = output

            # ==========================================
            # Discovery stage: extract live hosts
            # ==========================================
            if state.get("stage") == "discovery" and command.startswith("nmap"):
                hosts = ExecutionAgent._parse_discovery_hosts(output)
                state["discovered_hosts"] = hosts
                print(f"[Execution Agent] Discovered {len(hosts)} host(s): {hosts}\n")

            # ==========================================
            # Enumeration stage: parse + merge
            # ==========================================
            elif state.get("stage") == "enumeration" and command.startswith("nmap"):
                ExecutionAgent._merge_structured_result(state, output)

        except subprocess.TimeoutExpired:
            state["execution_output"] = "Execution failed: timeout exceeded."
        except Exception as e:
            state["execution_output"] = f"Execution error: {str(e)}"

        print("\n[Execution Agent] Finished.\n")
        return state

    # ==========================================
    # Helpers
    # ==========================================

    @staticmethod
    def _run_ssh_command(ip: str, username: str, password: str, command: str) -> str:
        """Exécute une commande Bash sur cible distante via SSH."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(hostname=ip, username=username, password=password, timeout=10)
            stdin, stdout, stderr = client.exec_command(command)
            out = stdout.read().decode('utf-8', errors='replace')
            err = stderr.read().decode('utf-8', errors='replace')
            return out + (f"\nErrors: {err}" if err else "")
        except Exception as e:
            return f"SSH Connection Failed: {str(e)}"
        finally:
            client.close()

    @staticmethod
    def _strip_fingerprints(output: str) -> str:
        return ExecutionAgent._FINGERPRINT_BLOCK_PATTERN.sub("", output).strip()

    @staticmethod
    def _parse_discovery_hosts(output: str) -> list[str]:
        found = ExecutionAgent._NMAP_HOST_PATTERN.findall(output)
        return list(dict.fromkeys(found))

    @staticmethod
    def _merge_structured_result(state: AuditState, output: str) -> None:
        parsed_hosts = NmapParser.parse(output)
        if "structured_hosts" not in state:
            state["structured_hosts"] = {}

        for new_host in parsed_hosts:
            existing = state["structured_hosts"].get(new_host.ip_address)
            if existing is None:
                state["structured_hosts"][new_host.ip_address] = new_host
                continue

            merged_status = new_host.status if new_host.status.value == "up" else existing.status
            merged_mac = existing.mac_address or new_host.mac_address
            merged_vendor = existing.vendor or new_host.vendor
            merged_os_info = existing.os_info or new_host.os_info

            ports_by_number = {p.port: p for p in existing.ports}
            for port in new_host.ports:
                current = ports_by_number.get(port.port)
                if current is None or (current.version is None and port.version is not None):
                    ports_by_number[port.port] = port

            merged_ports = list(ports_by_number.values())
            state["structured_hosts"][new_host.ip_address] = HostResult(
                ip_address=new_host.ip_address,
                status=merged_status,
                mac_address=merged_mac,
                vendor=merged_vendor,
                os_info=merged_os_info,
                ports=merged_ports,
                raw_output=existing.raw_output + "\n---\n" + new_host.raw_output,
            )