"""
Tool used to parse raw Nmap output into structured HostResult objects.

Handles discovery-stage output (-sn, host status + MAC only) and
enumeration-stage output (-sS/-sV/-O), including:
  - the port table
  - the "Service Info: OS: ..." guess that -sV sometimes produces
  - the REAL -O OS fingerprint, in either of its two formats:
      "OS details: <exact match>"
      "Aggressive OS guesses: <guess 1> (XX%), <guess 2> (YY%), ..."
"""

import re

from backend.models.host import HostResult, HostStatus, PortInfo


class NmapParser:
    """
    Parses raw Nmap stdout into a list of structured HostResult objects.
    """

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
    # NOTE: separators use [ \t]+ (space/tab only) instead of \s+, and the
    # version group is [^\n]+ instead of .+. \s+ also matches "\n", so on a
    # port line with NO version (e.g. "3389/tcp open  ms-wbt-server") the
    # old pattern would swallow the newline and capture the *next* line's
    # text as this port's version — corrupting both ports. Restricting the
    # separators/version group to same-line characters fixes that.
    _PORT_LINE_PATTERN = re.compile(
        r"^(\d+)/(tcp|udp)[ \t]+(\S+)[ \t]+(\S+)(?:[ \t]+([^\n]+))?$",
        re.MULTILINE
    )

    _OS_INFO_PATTERN = re.compile(
        r"Service Info:.*?OSs?:\s*([^;\n]+)"
    )

    _OS_DETAILS_PATTERN = re.compile(
        r"OS details:\s*([^\n]+)"
    )

    _OS_GUESS_PATTERN = re.compile(
        r"Aggressive OS guesses:\s*([^,\n]+?)\s*\((\d+)%\)"
    )

    @classmethod
    def parse(cls, output: str) -> list[HostResult]:
        blocks = cls._HOST_BLOCK_PATTERN.findall(output)
        results = []
        for block in blocks:
            host = cls._parse_host_block(block)
            if host is not None:
                results.append(host)
        return results

    @classmethod
    def _parse_host_block(cls, block: str) -> HostResult | None:
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

        os_info, os_confidence = cls._parse_os_info(block)
        ports = cls._parse_ports(block)

        return HostResult(
            ip_address=ip_address,
            status=status,
            mac_address=mac_address,
            vendor=vendor,
            os_info=os_info,
            os_confidence=os_confidence,
            ports=ports,
            raw_output=block.strip(),
        )

    @classmethod
    def _parse_os_info(cls, block: str) -> tuple[str | None, int | None]:
        """
        Retourne (os_info, os_confidence).
        - "OS details:" (match exact) -> confidence = 100
        - "Aggressive OS guesses:" -> confidence = pourcentage parsé
        - "Service Info: OS:" (sous-produit de -sV, pas de %) -> confidence = None
        """
        match = cls._OS_DETAILS_PATTERN.search(block)
        if match:
            return (match.group(1).strip(), 100)

        match = cls._OS_GUESS_PATTERN.search(block)
        if match:
            return (match.group(1).strip(), int(match.group(2)))

        match = cls._OS_INFO_PATTERN.search(block)
        if match:
            return (match.group(1).strip(), None)

        return (None, None)

    @classmethod
    def _parse_ports(cls, block: str) -> list[PortInfo]:
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