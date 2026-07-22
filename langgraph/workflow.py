"""
OddNet Workflow.

Supervisor-driven audit workflow.
The workflow executes nodes according to Supervisor decisions.
"""

from backend.agents.supervisor_agent import SupervisorAgent
from backend.agents.network_agent import NetworkAgent
from backend.agents.command_agent import CommandAgent
from backend.agents.execution_agent import ExecutionAgent
from backend.agents.report_agent import ReportAgent
from backend.agents.access_strategy_agent import AccessStrategyAgent
from backend.agents.identity_agent import IdentityCollectionAgent
from backend.guardrails.command_validator import CommandValidator
from backend.agents.classification_agent import ClassificationAgent
from backend.agents.collector_agent import CollectorAgent
from backend.agents.correlation_agent import CorrelationAgent
from backend.models.validation import ValidationInfo, ValidationAction
from backend.models.state import get_current_key

# Politique d'énumération : 3 commandes distinctes par host découvert.
DEFAULT_ENUMERATION_COMMANDS = ["-sS", "-sV", "-sn"]


class Workflow:

    @staticmethod
    def run(state):

        print("\n========== ODDNET AUDIT ==========\n")

        while True:

            # Supervisor decides next action
            next_step = SupervisorAgent.next_step(state)

            print(
                f"\nSupervisor decision --> {next_step}\n"
            )

            # ==========================================
            # Network Agent
            # ==========================================
            if next_step == "network":
                print("Collecting network information...\n")
                state = NetworkAgent.run(state)

            # ==========================================
            # Command Agent
            # ==========================================
            elif next_step == "command":
                print("Generating command...\n")
                state = CommandAgent.run(state)

                # Reset validation pipeline
                state["guardrail_status"] = None
                state["validation"] = None

            # ==========================================
            # Guardrail
            # ==========================================
            elif next_step == "guardrail":
                command = state["current_command"]

                # Validation avec prise en compte du stage actuel
                valid, message = CommandValidator.validate(
                    command.command, state.get("stage")
                )

                print(message)

                if valid:
                    state["guardrail_status"] = "Approved"
                else:
                    state["guardrail_status"] = "Blocked"

            # ==========================================
            # Human Validation (STRICTEMENT MANUELLE)
            # ==========================================
            elif next_step == "human_validation":
                command = state["current_command"]

                print("\n========== PROPOSED COMMAND ==========\n")
                print(f"Command      : {command.command}")
                print(f"Objective    : {command.objective}")
                print(f"Description  : {command.description}")

                print("\nArguments:")
                for arg in command.arguments:
                    print(f"  {arg.argument} -> {arg.explanation}")

                print(f"\nRisk Level        : {command.risk_level.value}")
                print(f"Estimated Duration: {command.estimated_duration}")
                print(f"Expected Impact   : {command.impact}")
                print(f"Justification     : {command.justification}")

                print("\n========================================\n")

                print("Engineer Decision")
                print("1 -> Approve")
                print("2 -> Reject")
                print("3 -> Modify")

                choice = input("\nChoice : ")

                if choice == "1":
                    state["validation"] = ValidationInfo(
                        action="Approve"
                    )
                elif choice == "2":
                    state["validation"] = ValidationInfo(
                        action="Reject"
                    )
                elif choice == "3":
                    comment = input(
                        "\nWhat would you like to modify? "
                    )
                    state["validation"] = ValidationInfo(
                        action="Modify",
                        comments=comment
                    )
                else:
                    print("\nInvalid choice. Rejecting command.\n")
                    state["validation"] = ValidationInfo(
                        action="Reject"
                    )

            # ==========================================
            # Execution Agent
            # ==========================================
            elif next_step == "execution":
                print("Executing command...\n")
                state = ExecutionAgent.run(state)

            # ==========================================
            # Access Strategy Agent
            # ==========================================
            elif next_step == "access_strategy":
                state = AccessStrategyAgent.run(state)
                
                # TRANSITION VERS LA PHASE 3 (Identity Collection)
                state["stage"] = "identity_collection"
                state["current_host_index"] = 0

            # ==========================================
            # Identity Collection Agent (Phase 3)
            # ==========================================
            elif next_step == "identity_collection":
                print("Collecting Identity information via SSH...\n")
                state = IdentityCollectionAgent.run(state)
                
                state["guardrail_status"] = None
                state["validation"] = None

            # ==========================================
            # Classification Agent (Phase 4)
            # ==========================================
            elif next_step == "classification":
                print("Refining host classifications (Phase 4)...\n")
                state = ClassificationAgent.run(state)
                
                # Transition directe vers le collector (Phase 5)
                state["stage"] = "collector"

            # ==========================================
            # Collector Agent (Phase 5 - Tag Discovery)
            # ==========================================
            elif next_step == "collector":
                print("Running Tag Discovery and Collector Agent (Phase 5)...\n")
                state = CollectorAgent.run(state)
                
                # Transition vers la Phase 6 (Correlation)
                state["stage"] = "correlation"

            # ==========================================
            # Correlation Agent (Phase 6 - Vulnerability Analysis)
            # ==========================================
            elif next_step == "correlation":
                print("Running Vulnerability Correlation Agent (Phase 6)...\n")
                state = CorrelationAgent.run(state)
                
                # Transition finale vers la fin
                state["stage"] = "done"

            # ==========================================
            # Report Agent
            # ==========================================
            elif next_step == "report":
                print("Generating report...\n")

                state = ReportAgent.run(state)

                if state["stage"] == "discovery":
                    if state["discovered_hosts"]:
                        state["stage"] = "enumeration"
                        state["current_host_index"] = 0
                        state["current_command_index"] = 0
                        state.setdefault(
                            "commands_per_host",
                            DEFAULT_ENUMERATION_COMMANDS,
                        )
                    else:
                        print("Aucun host detecte lors du discovery scan.\n")
                        state["stage"] = "done"

                elif state["stage"] == "enumeration":
                    commands_per_host = state.get(
                        "commands_per_host", DEFAULT_ENUMERATION_COMMANDS
                    )

                    state["current_command_index"] += 1

                    if state["current_command_index"] >= len(commands_per_host):
                        state["current_command_index"] = 0
                        state["current_host_index"] += 1

                        if state["current_host_index"] >= len(state["discovered_hosts"]):
                            state["stage"] = "access_strategy"

                state["current_command"] = None
                state["guardrail_status"] = None
                state["validation"] = None
                state["execution_output"] = None

            # ==========================================
            # End
            # ==========================================
            elif next_step == "end":
                print("\n========== AUDIT FINISHED ==========\n")
                break

            else:
                print(f"Unknown step: {next_step}")
                break

        return state