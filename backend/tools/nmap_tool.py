"""
Tool used to execute an approved Nmap command.
"""

import subprocess


class NmapTool:
    """
    Executes an approved Nmap command.
    """

    @staticmethod
    def run(command: str) -> str:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            shell=True
        )

        return result.stdout