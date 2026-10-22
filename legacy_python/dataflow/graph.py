"""Graph construction helpers for data-flow traces."""

from __future__ import annotations

from pyattackmap.models import (
    DataFlowEdge,
    DataFlowGraph,
    DataFlowNode,
    DataFlowNodeKind,
)


class DataFlowGraphBuilder:
    """Builder for constructing explainable DataFlowGraph instances."""

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self._nodes: list[DataFlowNode] = []
        self._edges: list[DataFlowEdge] = []
        self._node_counter: int = 0

    def add_node(
        self,
        kind: DataFlowNodeKind,
        line: int,
        col: int,
        label: str,
        snippet: str = "",
    ) -> DataFlowNode:
        """Create and add a new DataFlowNode."""
        self._node_counter += 1
        node_id = f"node_{self._node_counter}"
        node = DataFlowNode(
            id=node_id,
            kind=kind,
            file=self.file_path,
            line=line,
            col=col,
            label=label,
            snippet=snippet,
        )
        self._nodes.append(node)
        return node

    def add_edge(self, source_id: str, target_id: str, label: str = "") -> DataFlowEdge:
        """Add a directed edge connecting source_id to target_id."""
        edge = DataFlowEdge(source_id=source_id, target_id=target_id, label=label)
        self._edges.append(edge)
        return edge

    def build(self) -> DataFlowGraph:
        """Return the finalized DataFlowGraph."""
        return DataFlowGraph(
            nodes=list(self._nodes),
            edges=list(self._edges),
        )

