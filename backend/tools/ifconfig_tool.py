"""
Tool used to execute ifconfig (or ip addr as fallback) and extract
network information on Linux.
"""

import re
import subprocess
import ipaddress

from backend.models.state import NetworkInfo


class IfconfigTool:
    """
    Executes ifconfig (falling back to `ip addr` + `ip route` if
    ifconfig is not installed) and extracts network information.
    Parses interface blocks individually to avoid mixing
    IP/mask from different network cards, and skips loopback.
    """

    @staticmethod
    def run() -> NetworkInfo:

        candidates = IfconfigTool._parse_ifconfig()

        if not candidates:
            candidates = IfconfigTool._parse_ip_addr()

        if not candidates:
            return {
                "ip_address": "",
                "subnet_mask": "",
                "gateway": "",
            }

        gateway = IfconfigTool._get_gateway()

        for candidate in candidates:
            candidate["gateway"] = gateway

        # Prefer the candidate whose subnet contains the gateway
        if gateway:
            for candidate in candidates:
                try:
                    network = ipaddress.ip_network(
                        f"{candidate['ip_address']}/{candidate['subnet_mask']}",
                        strict=False,
                    )
                    if ipaddress.ip_address(gateway) in network:
                        return candidate
                except (ValueError, KeyError):
                    continue

        return candidates[0]

    @staticmethod
    def _parse_ifconfig():
        try:
            result = subprocess.run(
                ["ifconfig"],
                capture_output=True,
                encoding="utf-8",
                errors="ignore",
            )
        except FileNotFoundError:
            return []

        output = result.stdout
        if not output:
            return []

        blocks = re.split(r"\n(?=\S)", output)
        candidates = []

        for block in blocks:
            iface_match = re.match(r"^(\S+?):", block)
            if not iface_match:
                continue
            iface = iface_match.group(1)
            if iface == "lo":
                continue

            ip_match = re.search(r"inet\s+([\d.]+)", block)
            if not ip_match:
                continue

            mask_match = re.search(r"netmask\s+([\d.]+)", block)

            candidates.append({
                "ip_address": ip_match.group(1),
                "subnet_mask": mask_match.group(1) if mask_match else "",
                "gateway": "",
            })

        return candidates

    @staticmethod
    def _parse_ip_addr():
        try:
            result = subprocess.run(
                ["ip", "addr"],
                capture_output=True,
                encoding="utf-8",
                errors="ignore",
            )
        except FileNotFoundError:
            return []

        output = result.stdout
        if not output:
            return []

        blocks = re.split(r"\n(?=\d+:\s)", output)
        candidates = []

        for block in blocks:
            iface_match = re.match(r"^\d+:\s+(\S+?):", block)
            if not iface_match:
                continue
            iface = iface_match.group(1)
            if iface == "lo":
                continue

            ip_match = re.search(r"inet\s+([\d.]+)/(\d+)", block)
            if not ip_match:
                continue

            prefix_len = int(ip_match.group(2))
            subnet_mask = str(ipaddress.IPv4Network(
                f"0.0.0.0/{prefix_len}"
            ).netmask)

            candidates.append({
                "ip_address": ip_match.group(1),
                "subnet_mask": subnet_mask,
                "gateway": "",
            })

        return candidates

    @staticmethod
    def _get_gateway() -> str:
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                encoding="utf-8",
                errors="ignore",
            )
            match = re.search(r"default via ([\d.]+)", result.stdout)
            if match:
                return match.group(1)
        except FileNotFoundError:
            pass

        try:
            result = subprocess.run(
                ["route", "-n"],
                capture_output=True,
                encoding="utf-8",
                errors="ignore",
            )
            for line in result.stdout.splitlines():
                if line.startswith("0.0.0.0"):
                    parts = line.split()
                    if len(parts) > 1:
                        return parts[1]
        except FileNotFoundError:
            pass

        return ""