"""
OddNet Guardrail.

This module validates commands before they are shown to the engineer.
"""

import shlex


class CommandValidator:

    ALLOWED_TOOLS = [
        "nmap",
        "echo",
        "whoami",
        "uname",
        "hostname",
        "cat",
        "ver",
        "ls",
        "whoami",
        "dir"
    ]

    FORBIDDEN_FLAGS = [
        "-T5",
        "-A",
        "-O",
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
    def validate(cls, command: str) -> tuple[bool, str]:

        if not command.strip():
            return False, "Empty command."

        try:
            tokens = shlex.split(command)
        except Exception:
            return False, "Invalid command syntax."

        tool = tokens[0].lower()

        if tool not in cls.ALLOWED_TOOLS:
            return False, f"{tool} is not allowed."

        for token in tokens:
            if token in cls.FORBIDDEN_FLAGS:
                return False, f"Forbidden argument detected: {token}"

        forbidden_chars = [";", "&", "|", ">", "<"]

        for char in forbidden_chars:
            if char in command:
                return False, "Command injection detected."

        return True, "Command validated."