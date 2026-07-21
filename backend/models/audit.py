"""
Schemas related to audit information.

This module defines:
- Audit status
- Audit information
"""

from datetime import datetime, UTC
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# ==========================================================
# ENUMS
# ==========================================================

class AuditStatus(str, Enum):
    """
    Current audit status.
    """

    CREATED = "Created"
    IN_PROGRESS = "In Progress"
    COMPLETED = "Completed"


# ==========================================================
# AUDIT INFORMATION
# ==========================================================

class AuditInfo(BaseModel):
    """
    Stores the information of a network audit.
    """

    audit_id: UUID = Field(
        default_factory=uuid4,
        description="Unique audit identifier."
    )

    company: str = Field(
        ...,
        min_length=2,
        max_length=100,
        description="Company requesting the audit."
    )

    engineer: str = Field(
        ...,
        min_length=2,
        max_length=100,
        description="Engineer responsible for the audit."
    )

    objective: str = Field(
        ...,
        min_length=5,
        description="Audit objective."
    )

    status: AuditStatus = Field(
        default=AuditStatus.CREATED,
        description="Current audit status."
    )

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Audit creation date."
    )