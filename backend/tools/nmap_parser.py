"""
Tool used to parse raw Nmap output into structured HostResult objects.

Handles both discovery-stage output (-sn, host status + MAC only)
and enumeration-stage output (-sV etc., includes a port table and,
when available, an OS guess extracted from the "Service Info" line
produced by Nmap's own service/version detection — no dedicated OS
scan (-O) is performed).
"""

import re

from backend.models.host import HostResult, HostStatus, PortInfo


class NmapParser:
    """
    Parses raw Nmap stdout into a list of structured HostResult objects.
    """

    # Splits the output into one block per host, starting at each
    # "Nmap scan report for ..." line.
    _HOST_BLOCK_PATTERN = re.compile(
        r"Nmap scan report for.*?(?=Nmap scan report for|\Z)",
        re.DOTALL
    )

    _IP_PATTERN = re.compile(
        r"Nmap scan report for (?:\S+ \()?(\d{1,3}(?:\.\d{1,3}){3})\)?"
    )

    _STATUS_PATTERN = re.compile(
        r"Host is (up|down)",
        re.IGNORECASE
    )

    _MAC_PATTERN = re.compile(
        r"MAC Address:\s*([0-9A-Fa-f:]{17})(?:\s*\(([^)]+)\))?"
    )

    # Matches lines like: "22/tcp   open  ssh     OpenSSH 9.0"
    _PORT_LINE_PATTERN = re.compile(
        r"^(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)(?:\s+(.+))?$",
        re.MULTILINE
    )

    # Matches: "Service Info: OS: Windows; CPE: ..."
    #      or: "Service Info: OSs: Linux, Windows; CPE: ..."
    # Captures whatever is between "OS:"/"OSs:" and the next ";" or
    # end of line.
    _OS_INFO_PATTERN = re.compile(
        r"Service Info:.*?OSs?:\s*([^;\n]+)"
    )

    @classmethod
    def parse(cls, output: str) -> list[HostResult]:
        """
        Parse the full raw Nmap output (potentially multiple hosts)
        into a list of HostResult objects.
        """

        blocks = cls._HOST_BLOCK_PATTERN.findall(output)

        results = []

        for block in blocks:

            host = cls._parse_host_block(block)

            if host is not None:
                results.append(host)

        return results

    @classmethod
    def _parse_host_block(cls, block: str) -> HostResult | None:
        """
        Parse a single host's block of output into a HostResult.
        Returns None if no IP address could be found (malformed block).
        """

        ip_match = cls._IP_PATTERN.search(block)

        if not ip_match:
            return None

        ip_address = ip_match.group(1)

        status_match = cls._STATUS_PATTERN.search(block)
        status = (
            HostStatus.UP
            if status_match and status_match.group(1).lower() == "up"
            else HostStatus.DOWN
        )

        mac_match = cls._MAC_PATTERN.search(block)
        mac_address = mac_match.group(1) if mac_match else None
        vendor = mac_match.group(2) if mac_match and mac_match.group(2) else None

        os_info = cls._parse_os_info(block)

        ports = cls._parse_ports(block)

        return HostResult(
            ip_address=ip_address,
            status=status,
            mac_address=mac_address,
            vendor=vendor,
            os_info=os_info,
            ports=ports,
            raw_output=block.strip(),
        )

    @classmethod
    def _parse_os_info(cls, block: str) -> str | None:
        """
        Extract the OS guess from Nmap's "Service Info: OS: ..." line,
        if present. This is a byproduct of -sV service detection, not
        a dedicated OS scan (-O), so it may be absent or approximate.
        """

        match = cls._OS_INFO_PATTERN.search(block)

        return match.group(1).strip() if match else None

    @classmethod
    def _parse_ports(cls, block: str) -> list[PortInfo]:
        """
        Parse the port table (present only during enumeration scans)
        into a list of PortInfo objects. Returns [] if no port table
        is present (e.g. discovery-stage -sn output).
        """

        ports = []

        for match in cls._PORT_LINE_PATTERN.finditer(block):

            port_number, protocol, state, service, version = match.groups()

            ports.append(
                PortInfo(
                    port=int(port_number),
                    protocol=protocol,
                    state=state,
                    service=service if service != "unknown" else None,
                    version=version.strip() if version else None,
                )
            )

        return ports