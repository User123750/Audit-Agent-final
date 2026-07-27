"""
OddNet Entry Point.
"""

from backend.models.audit import AuditInfo
from backend.models.state import AuditState, DEFAULT_ENUMERATION_COMMANDS

from core_langgraph.graph import graph


def main():

    print("=" * 60)
    print("ODDNET")
    print("AI Network Audit Assistant")
    print("=" * 60)

    company = input("Company : ")
    engineer = input("Engineer : ")
    objective = input("Audit Objective : ")

    audit = AuditInfo(
        company=company,
        engineer=engineer,
        objective=objective,
    )

    state: AuditState = {
        "audit": audit,
        "network_info": None,
        "command_history": [],
        "current_command": None,
        "guardrail_status": None,
        "validation": None,
        "execution_output": None,
        "report": None,
        "stage": "discovery",
        "discovered_hosts": [],
        "current_host_index": 0,
        "current_command_index": 0,
        "commands_per_host": DEFAULT_ENUMERATION_COMMANDS,
        "host_results": {},
        "partial_reports": {},
        "structured_hosts": {},
        "access_strategies": {},
        "classifications": {},
        "asset_tags": {},
        "vulnerabilities": {},
        "batch_approved": None,
    }

    result = graph.invoke(state, config={"recursion_limit": 500})

    print("\n")
    print("=" * 60)
    print("FINAL REPORT")
    print("=" * 60)
    print(result["report"])


if __name__ == "__main__":
    main()