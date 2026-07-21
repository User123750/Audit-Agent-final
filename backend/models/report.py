"""
Schemas related to the final audit report.
"""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from backend.models.audit import AuditInfo
from backend.models.command import CommandInfo
from backend.models.validation import ValidationInfo


class ReportInfo(BaseModel):
    """
    Final audit report.
    """

    report_id: UUID = Field(
        default_factory=uuid4,
        description="Unique report identifier."
    )

    audit: AuditInfo = Field(
        ...,
        description="Audit information."
    )

    network_information: dict = Field(
        default_factory=dict,
        description="Collected network information."
    )

    approved_command: CommandInfo = Field(
        ...,
        description="Validated command."
    )

    validation: ValidationInfo = Field(
        ...,
        description="Engineer validation."
    )

    execution_output: str = Field(
        ...,
        description="Execution output."
    )

    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Report generation date."
    )