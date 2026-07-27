"""
OddNet Guardrail.

This module validates commands before they are shown to the engineer.
"""

import shlex


class CommandValidator:

    # CORRECTION BUG 4 : Séparation stricte des outils par étape
    NMAP_TOOLS = ["nmap"]
    
    IDENTITY_TOOLS = [
        "echo",
        "whoami",
        "id",
        "uname",
        "hostname",
        "hostnamectl",
        "systemd-detect-virt",
        "cat",
        "ver",
        "systeminfo",
        "ls",
        "dir"
    ]

    # -O retiré de cette liste : autorisé explicitement par l'encadrant
    # pour le fingerprinting OS avec pourcentage de confiance. Nécessite
    # des privilèges administrateur sur Windows (raw packet crafting),
    # sinon échoue silencieusement ou renvoie une erreur.
    FORBIDDEN_FLAGS = [
        "-T5",
        "-A",
        "-sU",
        "-iR",
        "--script",
        "--script-args",
        "--min-rate",
        "-oG",
        "-oX",
        "-oN"
    ]

    @classmethod
    def validate(cls, command: str, stage: str = None) -> tuple[bool, str]:

        if not command.strip():
            return False, "Empty command."

        try:
            tokens = shlex.split(command)
        except Exception:
            return False, "Invalid command syntax."

        tool = tokens[0].lower()

        # Validation dépendante de l'étape de l'audit
        if stage in ["discovery", "enumeration"]:
            allowed = cls.NMAP_TOOLS
        elif stage == "identity_collection":
            allowed = cls.IDENTITY_TOOLS
        else:
            # Rétrocompatibilité si le stage n'est pas fourni par workflow.py
            allowed = cls.NMAP_TOOLS + cls.IDENTITY_TOOLS

        if tool not in allowed:
            return False, f"{tool} is not allowed in stage: {stage or 'unknown'}."

        # On vérifie les flags Nmap uniquement si c'est une commande Nmap
        if tool == "nmap":
            for token in tokens:
                if token in cls.FORBIDDEN_FLAGS:
                    return False, f"Forbidden argument detected: {token}"

        # Protection universelle contre l'injection de commandes
        forbidden_chars = [";", "&", "|", ">", "<"]
        for char in forbidden_chars:
            if char in command:
                return False, "Command injection detected (multi-commands not allowed)."

        return True, "Command validated."