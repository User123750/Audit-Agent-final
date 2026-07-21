"""
Utilities for parsing network information.
"""

import ipaddress


class NetworkParser:

    @staticmethod
    def network_address(ip: str, mask: str) -> str:
        """
        Convert IP + subnet mask into CIDR network.
        """

        network = ipaddress.IPv4Network(
            f"{ip}/{mask}",
            strict=False
        )

        return str(network)

    @staticmethod
    def is_valid_ip(ip: str) -> bool:

        try:
            ipaddress.ip_address(ip)
            return True

        except ValueError:
            return False