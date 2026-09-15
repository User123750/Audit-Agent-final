"""
LangChain tools for the OddNet Audit Agent.

The existing LangGraph pipeline is NOT modified or removed.
"""

import ipaddress
import subprocess
import os
import paramiko
from langchain_core.tools import tool
import json
import ollama

from backend.models.classification import HostClassification

def _validate_cidr(subnet: str) -> str:
    
    """
    Validate that the provided value is a valid IPv4 network in CIDR notation.
    """
    try:
        network = ipaddress.ip_network(subnet, strict=False)

        if network.version != 4:
            raise ValueError("Only IPv4 networks are supported.")

        return str(network)

    except ValueError as exc:
        raise ValueError(
            f"Invalid IPv4 subnet: {subnet}"
        ) from exc


@tool
def run_nmap_discovery(subnet: str) -> str:
    
    """
    Discover active hosts on an IPv4 subnet using Nmap host discovery.

    The subnet must be provided in CIDR notation, for example:
    192.168.1.0/24.

    This tool only performs host discovery and does not perform
    a port scan.
    """
    validated_subnet = _validate_cidr(subnet)

    command = [
        "nmap",
        "-sn",
        validated_subnet,
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        shell=False,
        check=False,
    )

    if result.returncode != 0:
        return f"Nmap discovery failed:\n{result.stderr}"

    return result.stdout
run_nmap_discovery.metadata = {
    "requires_approval": True
}

@tool
def run_nmap_syn_scan(target: str) -> str:
    """
    Perform a TCP SYN scan against a validated IPv4 host.

    The target must be a valid IPv4 address, for example:
    192.168.1.10.

    This tool is used to identify open TCP ports.
    """
    try:
        ip = ipaddress.ip_address(target)

        if ip.version != 4:
            raise ValueError("Only IPv4 addresses are supported.")

    except ValueError as exc:
        raise ValueError(
            f"Invalid IPv4 address: {target}"
        ) from exc

    command = [
        "nmap",
        "-sS",
        target,
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        shell=False,
        check=False,
    )

    if result.returncode != 0:
        return f"Nmap SYN scan failed:\n{result.stderr}"

    return result.stdout
run_nmap_syn_scan.metadata = {
    "requires_approval": True
}


@tool
def run_nmap_version_scan(target: str) -> str:
    """
    Detect the versions of services running on a validated IPv4 host.

    The target must be a valid IPv4 address, for example:
    192.168.1.10.

    This tool performs Nmap service and version detection.
    """
    try:
        ip = ipaddress.ip_address(target)

        if ip.version != 4:
            raise ValueError("Only IPv4 addresses are supported.")

    except ValueError as exc:
        raise ValueError(
            f"Invalid IPv4 address: {target}"
        ) from exc

    command = [
        "nmap",
        "-sV",
        target,
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        shell=False,
        check=False,
    )

    if result.returncode != 0:
        return f"Nmap version scan failed:\n{result.stderr}"

    return result.stdout
run_nmap_version_scan.metadata = {
    "requires_approval": True
}

@tool
def run_nmap_ping_scan(target: str) -> str:
    """
    Perform an Nmap ping scan against a validated IPv4 host.

    The target must be a valid IPv4 address, for example:
    192.168.1.10.

    This tool checks whether the target host responds to Nmap host discovery.
    """
    try:
        ip = ipaddress.ip_address(target)

        if ip.version != 4:
            raise ValueError("Only IPv4 addresses are supported.")

    except ValueError as exc:
        raise ValueError(
            f"Invalid IPv4 address: {target}"
        ) from exc

    command = [
        "nmap",
        "-sn",
        target,
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        shell=False,
        check=False,
    )

    if result.returncode != 0:
        return f"Nmap ping scan failed:\n{result.stderr}"

    return result.stdout

run_nmap_ping_scan.metadata = {
    "requires_approval": True
}
@tool
def run_nmap_os_detection(target: str) -> str:
    """
    Detect the operating system of a validated IPv4 host using Nmap.

    The target must be a valid IPv4 address, for example:
    192.168.1.10.

    This tool performs Nmap operating system detection.
    """
    try:
        ip = ipaddress.ip_address(target)

        if ip.version != 4:
            raise ValueError("Only IPv4 addresses are supported.")

    except ValueError as exc:
        raise ValueError(
            f"Invalid IPv4 address: {target}"
        ) from exc

    command = [
        "nmap",
        "-O",
        target,
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        shell=False,
        check=False,
    )

    if result.returncode != 0:
        return f"Nmap OS detection failed:\n{result.stderr}"

    return result.stdout
run_nmap_os_detection.metadata = {
    "requires_approval": True
}
@tool
def run_identity_command(
    target: str,
    os_family: str,
) -> str:
    """
    Run one safe, read-only OS-identification command against a host
    through SSH.

    The target must be a valid IPv4 address.
    The OS family must be one of: linux, windows, unknown.

    The command itself is selected internally from a strict whitelist.
    The LLM cannot provide an arbitrary shell command.
    """
    # Validate target
    try:
        ip = ipaddress.ip_address(target)

        if ip.version != 4:
            raise ValueError("Only IPv4 addresses are supported.")

    except ValueError as exc:
        raise ValueError(
            f"Invalid IPv4 address: {target}"
        ) from exc

    # Normalize and validate OS family
    os_family = os_family.lower().strip()

    allowed_families = {
        "linux",
        "windows",
        "unknown",
    }

    if os_family not in allowed_families:
        raise ValueError(
            "Invalid os_family. Expected: linux, windows or unknown."
        )

    # Strict command whitelist.
    # The LLM never provides the command itself.
    commands = {
        "linux": "uname -a",
        "windows": "hostname",
        "unknown": "hostname",
    }

    command = commands[os_family]

    # Credentials come from the environment.
    username = os.getenv("SSH_USERNAME")
    password = os.getenv("SSH_PASSWORD")

    if not username or not password:
        raise RuntimeError(
            "SSH credentials are not configured in the environment."
        )

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(
            paramiko.AutoAddPolicy()
        )

        client.connect(
            hostname=target,
            username=username,
            password=password,
            timeout=10,
        )

        stdin, stdout, stderr = client.exec_command(command)

        output = stdout.read().decode("utf-8").strip()
        error = stderr.read().decode("utf-8").strip()

        client.close()

        if error:
            return f"SSH identity command failed:\n{error}"

        return output

    except paramiko.AuthenticationException:
        return "SSH authentication failed."

    except Exception as exc:
        return f"SSH connection failed: {exc}"

run_identity_command.metadata = {
    "requires_approval": True
}

@tool
def lookup_cve(keyword: str, max_results: int = 5) -> str:
    """
    Search the NVD for real CVEs related to a detected service or version.

    The keyword can describe a service and version, for example:
    'OpenSSH 8.2' or 'Apache 2.4.49'.

    This tool is read-only and does not execute commands.
    """
    keyword = keyword.strip()

    if not keyword:
        raise ValueError("The CVE search keyword cannot be empty.")

    if not 1 <= max_results <= 20:
        raise ValueError("max_results must be between 1 and 20.")

    from backend.tools.nvd_tool import NvdTool

    results = NvdTool.search_cves(
        keyword=keyword,
        max_results=max_results,
    )

    return str(results)

lookup_cve.metadata = {
    "requires_approval": False
}

@tool
def classify_asset(
    target: str,
    nmap_data: str,
    ssh_output: str = "",
) -> str:
    """
    Classify a discovered network asset into exactly one predefined asset class.

    The classification is based only on factual Nmap data and, when available,
    SSH identity output.

    Allowed classes are:
    Linux Endpoint, Windows Endpoint, Mac Endpoint,
    Single Server, Hypervisor, Unknown.

    Network equipment such as routers and firewalls must be classified as Unknown.
    This tool does not execute any network command.
    """
    try:
        ip = ipaddress.ip_address(target)

        if ip.version != 4:
            raise ValueError("Only IPv4 addresses are supported.")

    except ValueError as exc:
        raise ValueError(
            f"Invalid IPv4 address: {target}"
        ) from exc

    if not nmap_data.strip():
        return json.dumps(
            {
                "assigned_class": "Unknown",
                "justification": "No Nmap data available for this host."
            }
        )

    prompt = f"""
You are an expert network security auditor.

Your task is to classify the following network asset into EXACTLY ONE
of the predefined classes.

Target IP: {target}

--- FACTUAL DATA COLLECTED ---
Nmap Scan Data:
{nmap_data}

SSH Identity Output:
{ssh_output if ssh_output.strip() else "No SSH identity output available."}
------------------------------

Classification Rules:
- You must assign exactly ONE class from this list:
  Linux Endpoint, Windows Endpoint, Mac Endpoint,
  Single Server, Hypervisor, Unknown.
- You are strictly FORBIDDEN to create new classes.
- If the Nmap data indicates network equipment, a router, a firewall
  (e.g., FortiOS, FortiSSH), or if SSH access failed/is unavailable
  for a gateway, you MUST classify it as "Unknown".
- If the OS is Linux and it hosts multiple enterprise services
  (like HTTP, PostgreSQL, SMB), consider it a "Single Server".
- If the SSH identity clearly says Ubuntu/Debian with standard
  endpoint ports, it is a "Linux Endpoint".

Return ONLY a valid JSON object matching the requested schema with
both 'assigned_class' and a non-empty 'justification'.
No markdown, no explanations outside the JSON.
"""

    try:
        response = ollama.chat(
            model="llama3",
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            format=HostClassification.model_json_schema(),
        )

        content = response["message"]["content"].strip()

        if content.startswith("```json"):
            content = content[7:]

        if content.startswith("```"):
            content = content[3:]

        if content.endswith("```"):
            content = content[:-3]

        data = json.loads(content.strip())

        classification = HostClassification(**data)

        return json.dumps(
            {
                "assigned_class": classification.assigned_class.value,
                "justification": classification.justification,
            }
        )

    except Exception as exc:
        return json.dumps(
            {
                "assigned_class": "Unknown",
                "justification": f"Classification failed: {str(exc)}",
            }
        )
classify_asset.metadata = {
    "requires_approval": False
}
# Tools exposed to the new LangChain agent.
LANGCHAIN_TOOLS = [
    run_nmap_discovery,
    run_nmap_syn_scan,
    run_nmap_version_scan,
    run_nmap_ping_scan,
    run_nmap_os_detection,
    run_identity_command,
    lookup_cve,
    classify_asset,

]