"""
Schemas related to host scan results.
"""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ==========================================================
# ENUMS
# ==========================================================

class HostStatus(str, Enum):
    UP = "up"
    DOWN = "down"


# ==========================================================
# PORT INFO
# ==========================================================

class PortInfo(BaseModel):
    """
    One discovered port with its service/version details.
    """

    port: int = Field(
        ...,
        description="Port number."
    )

    protocol: str = Field(
        default="tcp",
        description="Protocol (tcp/udp)."
    )

    state: str = Field(
        ...,
        description="Port state (open, closed, filtered)."
    )

    service: Optional[str] = Field(
        default=None,
        description="Detected service name."
    )

    version: Optional[str] = Field(
        default=None,
        description="Detected service version, if available."
    )


# ==========================================================
# HOST RESULT
# ==========================================================

class HostResult(BaseModel):
    """
    Structured scan result for a single host.
    """

    ip_address: str = Field(
        ...,
        description="Host IP address."
    )

    status: HostStatus = Field(
        ...,
        description="Host status (up/down)."
    )

    mac_address: Optional[str] = Field(
        default=None,
        description="MAC address, if detected."
    )

    vendor: Optional[str] = Field(
        default=None,
        description="Vendor name inferred from the MAC address."
    )

    os_info: Optional[str] = Field(
        default=None,
        description="Operating system guessed by Nmap's service detection "
                     "(-sV), extracted from the 'Service Info: OS: ...' "
                     "line when present. No dedicated OS scan is performed."
    )

    os_confidence: Optional[int] = Field(
        default=None,
        description="Confidence percentage (0-100) associated with os_info. "
                     "100 for an exact -O 'OS details' match, the parsed "
                     "percentage for an 'Aggressive OS guesses' fallback, "
                     "or None when os_info comes only from the -sV "
                     "'Service Info' byproduct (no percentage available)."
    )

    ports: list[PortInfo] = Field(
        default_factory=list,
        description="Ports discovered during enumeration (empty during discovery stage)."
    )

    raw_output: str = Field(
        default="",
        description="Original raw Nmap output for this host (kept for traceability)."
    )