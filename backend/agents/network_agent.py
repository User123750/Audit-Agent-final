"""
Network Agent.

Runs ipconfig and updates the state.
"""

from backend.models.state import AuditState
from backend.tools.ipconfig_tool import IPConfigTool


class NetworkAgent:

    @staticmethod
    def run(state: AuditState) -> AuditState:

        network = IPConfigTool.run()

        state["network_info"] = network

        return state