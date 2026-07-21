"""
Schemas related to SSH access strategy generation.
"""

from pydantic import BaseModel, Field


class AccessStrategy(BaseModel):
    """
    Access strategy for a single host, combining static credential
    store data (username, credential_id) with the dynamically
    discovered SSH port (from Nmap scan results).
    """

    ip_address: str = Field(
        ...,
        description="Target host IP address."
    )

    username: str = Field(
        ...,
        description="SSH username (static, from credential store)."
    )

    port: int = Field(
        default=0,
        description="SSH port. 0 = not yet resolved / no SSH detected. "
                     "Filled dynamically from Nmap scan results."
    )

    credential_id: str = Field(
        ...,
        description="Reference to the credential in the secure store "
                     "(NOT the password itself)."
    )