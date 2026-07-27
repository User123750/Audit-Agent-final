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
    # Byproduct of -sV service detection, NOT a dedicated OS scan.
    _OS_INFO_PATTERN = re.compile(
        r"Service Info:.*?OSs?:\s*([^;\n]+)"
    )

    # Matches: "OS details: Linux 5.0 - 5.14"
    # This is -O's confident, exact match — takes priority when present.
    _OS_DETAILS_PATTERN = re.compile(
        r"OS details:\s*([^\n]+)"
    )

    # Matches: "Aggressive OS guesses: Linux 5.4 (92%), Linux 4.15 - 5.19 (91%), ..."
    # -O's fallback when it isn't fully confident. We keep only the FIRST
    # guess (highest confidence), including its percentage.
    _OS_GUESS_PATTERN = re.compile(
        r"Aggressive OS guesses:\s*([^,\n]+\(\d+%\))"
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
        Extract the OS fingerprint, preferring the most confident source:

          1. "OS details: ..."            -> -O exact match (best)
          2. "Aggressive OS guesses: ..."  -> -O best guess with % (fallback)
          3. "Service Info: OS: ..."       -> -sV byproduct (least specific)
        """

        match = cls._OS_DETAILS_PATTERN.search(block)
        if match:
            return match.group(1).strip()

        match = cls._OS_GUESS_PATTERN.search(block)
        if match:
            return match.group(1).strip()

        match = cls._OS_INFO_PATTERN.search(block)
        if match:
            return match.group(1).strip()

        return None

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