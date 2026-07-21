"""
Schemas related to command generation.
"""

from enum import Enum

from pydantic import BaseModel, Field


# ==========================================================
# ENUMS
# ==========================================================

class RiskLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


# ==========================================================
# COMMAND ARGUMENT
# ==========================================================

class CommandArgument(BaseModel):
    """
    One command argument with its explanation.
    """

    argument: str = Field(
        ...,
        description="Command argument."
    )

    explanation: str = Field(
        ...,
        description="Explanation of the argument."
    )


# ==========================================================
# COMMAND PROPOSAL
# ==========================================================

class CommandInfo(BaseModel):
    """
    Command proposed by the AI agent.
    """

    command: str = Field(
        ...,
        description="Generated command."
    )

    objective: str = Field(
        ...,
        description="Command objective."
    )

    description: str = Field(
        ...,
        description="Detailed description."
    )

    arguments: list[CommandArgument] = Field(
        default_factory=list,
        description="Command arguments."
    )

    risk_level: RiskLevel = Field(
        ...,
        description="Estimated risk level."
    )

    impact: str = Field(
        ...,
        description="Expected impact."
    )

    estimated_duration: str = Field(
        ...,
        description="Estimated execution duration."
    )

    justification: str = Field(
        ...,
        description="Reason why the command was selected."
    )