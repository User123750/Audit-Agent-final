"""
Tool used to execute ipconfig and extract network information.
"""

import re
import subprocess

from backend.models.state import NetworkInfo


class IPConfigTool:
    """
    Executes ipconfig and extracts network information.
    Parses adapter blocks individually to avoid mixing
    IP/mask/gateway from different network cards.
    """

    @staticmethod
    def run() -> NetworkInfo:

        result = subprocess.run(
            ["ipconfig"],
            capture_output=True,
            encoding="cp850",
            shell=True
        )

        output = result.stdout

        blocks = re.split(r"\n(?=\S.*:\s*\n)", output)

        candidates = []

        for block in blocks:

            ip_match = re.search(
                r"(?:IPv4|Adresse IPv4).*?:\s*([\d\.]+)",
                block,
                re.IGNORECASE,
            )

            if not ip_match:
                continue

            mask_match = re.search(
                r"(?:Subnet Mask|Masque de sous-réseau).*?:\s*([\d\.]+)",
                block,
                re.IGNORECASE,
            )

            gateway_match = re.search(
                r"(?:Default Gateway|Passerelle par défaut).*?:\s*([\d\.]+)",
                block,
                re.IGNORECASE,
            )

            candidates.append({
                "ip_address": ip_match.group(1),
                "subnet_mask": mask_match.group(1) if mask_match else "",
                "gateway": gateway_match.group(1) if gateway_match else "",
            })

        if not candidates:
            return {
                "ip_address": "",
                "subnet_mask": "",
                "gateway": "",
            }

        for candidate in candidates:
            if candidate["gateway"]:
                return candidate

        return candidates[0]