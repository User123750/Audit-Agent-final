"""
OddNet LangGraph.

This graph orchestrates the complete audit workflow:
discovery -> enumeration -> access_strategy -> identity_collection ->
classification -> collector -> correlation -> done.

Every step that touches the network or a remote host goes through the
Guardrail and the engineer's Human-In-The-Loop validation before
execution. The Supervisor is the ONLY place that decides what runs
next — no node ever routes to another node directly.
"""

# الصح هنا هو الاستيراد من المكتبة الرسمية الخارجية langgraph
from langgraph.graph import START, END, StateGraph

from backend.models.state import AuditState

from backend.agents.network_agent import NetworkAgent
from backend.agents.command_agent import CommandAgent
from backend.agents.execution_agent import ExecutionAgent
from backend.agents.report_agent import ReportAgent
from backend.agents.access_strategy_agent import AccessStrategyAgent
from backend.agents.identity_agent import IdentityAgent
from backend.agents.classification_agent import ClassificationAgent
from backend.agents.collector_agent import CollectorAgent
from backend.agents.correlation_agent import CorrelationAgent
from backend.agents.supervisor_agent import SupervisorAgent
from backend.agents.human_validation_agent import human_validation_node
from backend.guardrails.guardrail_node import guardrail_node


# ==========================================================
# GRAPH
# ==========================================================

builder = StateGraph(AuditState)


# ==========================================================
# NODES
# ==========================================================

builder.add_node("network", NetworkAgent.run)
builder.add_node("command", CommandAgent.run)
builder.add_node("guardrail", guardrail_node)
builder.add_node("human_validation", human_validation_node)
builder.add_node("execution", ExecutionAgent.run)
builder.add_node("report", ReportAgent.run)
builder.add_node("access_strategy", AccessStrategyAgent.run)
builder.add_node("identity_collection", IdentityAgent.run)
builder.add_node("classification", ClassificationAgent.run)
builder.add_node("collector", CollectorAgent.run)
builder.add_node("correlation", CorrelationAgent.run)


# ==========================================================
# ROUTING — le Supervisor décide TOUJOURS de la suite
# ==========================================================

def route(state: AuditState) -> str:
    return SupervisorAgent.next_step(state)


ROUTING_MAP = {
    "network": "network",
    "command": "command",
    "guardrail": "guardrail",
    "human_validation": "human_validation",
    "execution": "execution",
    "report": "report",
    "access_strategy": "access_strategy",
    "identity_collection": "identity_collection",
    "classification": "classification",
    "collector": "collector",
    "correlation": "correlation",
    "end": END,
}


# ==========================================================
# EDGES
# ==========================================================

builder.add_edge(START, "network")

for node_name in [
    "network",
    "command",
    "guardrail",
    "human_validation",
    "execution",
    "report",
    "access_strategy",
    "identity_collection",
    "classification",
    "collector",
    "correlation",
]:
    builder.add_conditional_edges(node_name, route, ROUTING_MAP)


# ==========================================================
# COMPILE
# ==========================================================

graph = builder.compile()