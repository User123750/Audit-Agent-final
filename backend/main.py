"""
OddNet Entry Point.
"""

from backend.models.audit import AuditInfo
from backend.models.state import AuditState

from langgraph.graph import graph


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

        objective=objective

    )

    state: AuditState = {

        "audit": audit,

        "network_info": None,

        "command_history": [],

        "current_command": None,

        "guardrail_status": "Pending",

        "validation": None,

        "execution_output": None,

        "report": None

    }

    result = graph.invoke(state)

    print("\n")

    print("=" * 60)

    print("FINAL REPORT")

    print("=" * 60)

    print(result["report"])


if __name__ == "__main__":
    main()