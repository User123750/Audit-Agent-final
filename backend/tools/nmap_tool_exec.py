"""
Tool used to execute an approved Nmap command.

Prend directement une liste d'arguments déjà validés —
jamais une string, jamais shell=True.
"""

import subprocess
from typing import List


class NmapTool:
    """
    Executes an approved Nmap command, given as an argument list.
    """

    @staticmethod
    def run(args: List[str]) -> str:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            shell=False,
            check=False,
        )

        if result.returncode != 0:
            return result.stderr

        return result.stdout