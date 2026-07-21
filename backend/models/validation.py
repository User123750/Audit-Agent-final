"""
Schemas related to engineer validation.
"""

from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field


# ==========================================================
# ENUMS
# ==========================================================

class ValidationAction(str, Enum):
    APPROVE = "Approve"
    REJECT = "Reject"
    MODIFY = "Modify"


# ==========================================================
# VALIDATION
# ==========================================================

class ValidationInfo(BaseModel):
    """
    Engineer validation.
    """

    action: ValidationAction = Field(
        ...,
        description="Decision taken by the engineer."
    )

    comments: str | None = Field(
        default=None,
        description="Optional engineer comments."
    )

    validated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Validation timestamp."
    )