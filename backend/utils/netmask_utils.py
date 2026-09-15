"""
Utilitaire de conversion netmask -> préfixe CIDR.

Nmap n'accepte pas la notation IP/255.255.255.0 — il faut la notation
CIDR (IP/24). Cette fonction convertit un netmask classique en préfixe.
"""

import ipaddress


def netmask_to_cidr(netmask: str) -> int:
    """Convertit '255.255.255.0' -> 24."""
    return ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen


def build_subnet_cidr(ip_address: str, subnet_mask: str) -> str:
    """Construit la notation CIDR complète attendue par nmap.
    Ex: build_subnet_cidr('192.168.3.13', '255.255.255.0') -> '192.168.3.0/24'
    """
    prefix = netmask_to_cidr(subnet_mask)
    network = ipaddress.IPv4Network(f"{ip_address}/{prefix}", strict=False)
    return str(network)  # ex: 192.168.3.0/24