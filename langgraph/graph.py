"""
OddNet LangGraph.

This graph orchestrates the complete audit workflow.
"""

from langgraph.graph import START, END, StateGraph

from backend.models.state import AuditState

from langgraph.workflow import Workflow


# ==========================================================
# GRAPH
# ==========================================================

builder = StateGraph(AuditState)


# ==========================================================
# NODE
# ==========================================================

builder.add_node(
    "workflow",
    Workflow.run
)


# ==========================================================
# EDGES
# ==========================================================

builder.add_edge(
    START,
    "workflow"
)

builder.add_edge(
    "workflow",
    END
)


# ==========================================================
# COMPILE
# ==========================================================

graph = builder.compile()