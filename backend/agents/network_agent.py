"""
Network Agent.

Runs ipconfig (Windows) or ifconfig (Linux) depending on the host OS
and updates the state.
"""

import platform

from backend.models.state import AuditState
from backend.tools.ipconfig_tool import IPConfigTool
from backend.tools.ifconfig_tool import IfconfigTool


class NetworkAgent:

    @staticmethod
    def run(state: AuditState) -> AuditState:

        if platform.system() == "Windows":
            network = IPConfigTool.run()
        else:
            network = IfconfigTool.run()

        state["network_info"] = network

        return state