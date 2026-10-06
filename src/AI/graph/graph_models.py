from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class GraphNode:
    """
    A node in the SentinelMesh Incident Intelligence Graph.
    """

    node_id: str
    node_type: str
    source: str
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """
    A deterministic relationship between two graph nodes.
    """

    source_id: str
    target_id: str
    relationship: str
    source: str
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IncidentGraph:
    """
    Complete graph representation of one SentinelMesh incident.
    """

    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)

    def add_node(self, node: GraphNode) -> None:
        """
        Add a node if a node with the same ID does not already exist.
        """

        if not any(existing.node_id == node.node_id for existing in self.nodes):
            self.nodes.append(node)

    def add_edge(self, edge: GraphEdge) -> None:
        """
        Add an edge if the same relationship does not already exist.
        """

        duplicate = any(
            existing.source_id == edge.source_id
            and existing.target_id == edge.target_id
            and existing.relationship == edge.relationship
            for existing in self.edges
        )

        if not duplicate:
            self.edges.append(edge)

    def get_node(self, node_id: str) -> GraphNode | None:
        """
        Return a node by ID.
        """

        for node in self.nodes:
            if node.node_id == node_id:
                return node

        return None

    def get_nodes_by_type(self, node_type: str) -> List[GraphNode]:
        """
        Return all nodes of a particular type.
        """

        return [
            node
            for node in self.nodes
            if node.node_type == node_type
        ]

    def get_edges_from(self, node_id: str) -> List[GraphEdge]:
        """
        Return all relationships originating from a node.
        """

        return [
            edge
            for edge in self.edges
            if edge.source_id == node_id
        ]

    def get_edges_to(self, node_id: str) -> List[GraphEdge]:
        """
        Return all relationships pointing to a node.
        """

        return [
            edge
            for edge in self.edges
            if edge.target_id == node_id
        ]

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the graph into a JSON-serializable dictionary.
        """

        return {
            "nodes": [
                {
                    "node_id": node.node_id,
                    "node_type": node.node_type,
                    "source": node.source,
                    "properties": node.properties,
                }
                for node in self.nodes
            ],
            "edges": [
                {
                    "source_id": edge.source_id,
                    "target_id": edge.target_id,
                    "relationship": edge.relationship,
                    "source": edge.source,
                    "properties": edge.properties,
                }
                for edge in self.edges
            ],
        }