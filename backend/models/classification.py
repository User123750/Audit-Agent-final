"""
Models for Phase 4: Classification Refinement.
"""
from enum import Enum
from pydantic import BaseModel, Field

class AssetClass(str, Enum):
    """
    The fixed set of predefined classes allowed by the platform.
    The LLM is NOT allowed to create new classes dynamically.
    """
    LINUX_ENDPOINT = "Linux Endpoint"
    WINDOWS_ENDPOINT = "Windows Endpoint"
    MAC_ENDPOINT = "Mac Endpoint"
    SINGLE_SERVER = "Single Server"
    HYPERVISOR = "Hypervisor"
    UNKNOWN = "Unknown"

class HostClassification(BaseModel):
    """
    The structured JSON output expected from the LLM during Phase 4.
    """
    assigned_class: AssetClass = Field(
        ..., 
        description="The exact class assigned to the host. Must be one of the predefined Enum values."
    )
    justification: str = Field(
        ...,
        description="Short explanation of why this class was chosen based on OS info, open ports, and SSH identity output."
    )