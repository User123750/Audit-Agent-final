import paramiko

def execute_ssh_command(ip, username, password, command):
    """
    Fonction li kat-simuli le moteur d'exécution.
    Kat-connecta b SSH, kat-lanci la commande, w katrje3 le résultat brut.
    """
    client = paramiko.SSHClient()
    
    # Accepter automatiquement les clés SSH inconnues (obligatoire f l'automatisation)
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        # Phase de connexion
        client.connect(hostname=ip, username=username, password=password, timeout=10)
        
        # Exécution dyal la commande bash li wjéd l'agent
        stdin, stdout, stderr = client.exec_command(command)
        
        # Récupération du résultat brut (stdout) w les erreurs (stderr)
        output = stdout.read().decode('utf-8').strip()
        error = stderr.read().decode('utf-8').strip()
        
        if error:
            # L'agent khassou y3ref ila kano des erreurs f l'exécution
            return {"status": "error", "result": error}
            
        # Ila kolchi daz mzyan, kanreddo le output
        return {"status": "success", "result": output}
            
    except paramiko.AuthenticationException:
        # Erreur dyal les mots de passe
        return {"status": "auth_error", "result": "Échec d'authentification: Username wla mot de passe ghaltin."}
    except Exception as e:
        # Ay erreur akhra (timeout, connexion refusée...)
        return {"status": "connection_error", "result": str(e)}
    finally:
        # Sedd la connexion dima bach matb9ach m3el9a
        client.close()