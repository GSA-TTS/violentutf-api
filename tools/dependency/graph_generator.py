"""Dependency graph generation and visualization tool for ViolentUTF API."""

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml
from structlog.stdlib import get_logger

logger = get_logger(__name__)


@dataclass
class GraphNode:
    """Represents a node in the dependency graph."""

    id: str
    label: str
    node_type: str
    criticality: str
    properties: Dict[str, Any]


@dataclass
class GraphEdge:
    """Represents an edge in the dependency graph."""

    source: str
    target: str
    edge_type: str
    properties: Dict[str, Any]


@dataclass
class DependencyGraph:
    """Represents a complete dependency graph."""

    nodes: List[GraphNode]
    edges: List[GraphEdge]
    metadata: Dict[str, Any]


class DependencyGraphGenerator:
    """Generate dependency graphs and visualizations."""

    def __init__(self, project_root: str = "."):
        """Initialize the graph generator."""
        self.project_root = Path(project_root)
        self.graphs: Dict[str, DependencyGraph] = {}

        logger.info("DependencyGraphGenerator initialized", project_root=str(self.project_root))

    def generate_service_graph(self, service_dependencies: List[Dict[str, Any]]) -> DependencyGraph:
        """Generate service-level dependency graph."""
        logger.info("Generating service dependency graph", services_count=len(service_dependencies))

        nodes = []
        edges = []

        # Create nodes for each service
        for service in service_dependencies:
            node = GraphNode(
                id=service["name"],
                label=service["name"],
                node_type="service",
                criticality=service.get("criticality", "medium"),
                properties={
                    "service_type": service.get("service_type", "unknown"),
                    "health_check": service.get("health_check"),
                    "ports": service.get("ports", []),
                    "volumes": service.get("volumes", []),
                    "networks": service.get("networks", []),
                },
            )
            nodes.append(node)

        # Create edges for dependencies
        for service in service_dependencies:
            for dependency in service.get("depends_on", []):
                edge = GraphEdge(
                    source=dependency,
                    target=service["name"],
                    edge_type="service_dependency",
                    properties={"condition": service.get("condition"), "dependency_type": "runtime"},
                )
                edges.append(edge)

        graph = DependencyGraph(
            nodes=nodes,
            edges=edges,
            metadata={
                "graph_type": "service_dependencies",
                "generated_at": datetime.now().isoformat(),
                "total_services": len(nodes),
                "total_dependencies": len(edges),
            },
        )

        self.graphs["service"] = graph
        logger.info("Service dependency graph generated", nodes=len(nodes), edges=len(edges))

        return graph

    def generate_application_graph(
        self,
        repository_deps: List[Dict[str, Any]],
        endpoint_deps: List[Dict[str, Any]],
        middleware_deps: List[Dict[str, Any]],
    ) -> DependencyGraph:
        """Generate application-level dependency graph."""
        logger.info("Generating application dependency graph")

        nodes = []
        edges = []

        # Add repository nodes
        for repo in repository_deps:
            node = GraphNode(
                id=f"repo_{repo['name']}",
                label=repo["name"],
                node_type="repository",
                criticality=repo.get("criticality", "medium"),
                properties={
                    "models": repo.get("models", []),
                    "tables": repo.get("tables", []),
                    "operations": repo.get("operations", []),
                },
            )
            nodes.append(node)

        # Add endpoint nodes
        for endpoint in endpoint_deps:
            node = GraphNode(
                id=f"endpoint_{endpoint['name']}",
                label=endpoint["name"],
                node_type="endpoint",
                criticality=endpoint.get("criticality", "medium"),
                properties={
                    "methods": endpoint.get("methods", []),
                    "auth_required": endpoint.get("auth_required", False),
                    "rate_limited": endpoint.get("rate_limited", False),
                },
            )
            nodes.append(node)

        # Add middleware nodes
        for middleware in middleware_deps:
            node = GraphNode(
                id=f"middleware_{middleware['name']}",
                label=middleware["name"],
                node_type="middleware",
                criticality=middleware.get("criticality", "medium"),
                properties={
                    "execution_order": middleware.get("order", 0),
                    "applies_to": middleware.get("applies_to", []),
                },
            )
            nodes.append(node)

        # Create edges for endpoint -> repository dependencies
        for endpoint in endpoint_deps:
            for repo_name in endpoint.get("repositories", []):
                edge = GraphEdge(
                    source=f"endpoint_{endpoint['name']}",
                    target=f"repo_{repo_name}",
                    edge_type="uses_repository",
                    properties={"usage_type": "data_access"},
                )
                edges.append(edge)

        # Create edges for middleware -> endpoint dependencies
        for endpoint in endpoint_deps:
            for middleware_name in endpoint.get("middleware", []):
                edge = GraphEdge(
                    source=f"middleware_{middleware_name}",
                    target=f"endpoint_{endpoint['name']}",
                    edge_type="processes_request",
                    properties={"processing_type": "middleware"},
                )
                edges.append(edge)

        graph = DependencyGraph(
            nodes=nodes,
            edges=edges,
            metadata={
                "graph_type": "application_dependencies",
                "generated_at": datetime.now().isoformat(),
                "total_components": len(nodes),
                "total_dependencies": len(edges),
            },
        )

        self.graphs["application"] = graph
        logger.info("Application dependency graph generated", nodes=len(nodes), edges=len(edges))

        return graph

    def generate_database_graph(self, model_deps: List[Dict[str, Any]]) -> DependencyGraph:
        """Generate database-level dependency graph."""
        logger.info("Generating database dependency graph", models_count=len(model_deps))

        nodes = []
        edges = []

        # Create nodes for each model/table
        for model in model_deps:
            node = GraphNode(
                id=f"model_{model['name']}",
                label=model["name"],
                node_type="model",
                criticality=model.get("criticality", "medium"),
                properties={
                    "table_name": model.get("table_name", model["name"].lower()),
                    "primary_key": model.get("primary_key", "id"),
                    "indexes": model.get("indexes", []),
                    "constraints": model.get("constraints", []),
                },
            )
            nodes.append(node)

        # Create edges for relationships
        for model in model_deps:
            for relationship in model.get("relationships", []):
                if relationship["type"] == "foreign_key":
                    edge = GraphEdge(
                        source=f"model_{model['name']}",
                        target=f"model_{relationship['target']}",
                        edge_type="foreign_key",
                        properties={
                            "cascade": relationship.get("cascade", "none"),
                            "nullable": relationship.get("nullable", True),
                        },
                    )
                    edges.append(edge)
                elif relationship["type"] == "many_to_many":
                    edge = GraphEdge(
                        source=f"model_{model['name']}",
                        target=f"model_{relationship['target']}",
                        edge_type="many_to_many",
                        properties={
                            "through_table": relationship.get("through_table"),
                            "backref": relationship.get("backref"),
                        },
                    )
                    edges.append(edge)

        graph = DependencyGraph(
            nodes=nodes,
            edges=edges,
            metadata={
                "graph_type": "database_dependencies",
                "generated_at": datetime.now().isoformat(),
                "total_models": len(nodes),
                "total_relationships": len(edges),
            },
        )

        self.graphs["database"] = graph
        logger.info("Database dependency graph generated", nodes=len(nodes), edges=len(edges))

        return graph

    def generate_mermaid_diagram(self, graph: DependencyGraph) -> str:
        """Generate Mermaid diagram from dependency graph."""
        logger.info("Generating Mermaid diagram", graph_type=graph.metadata.get("graph_type"))

        lines = []

        # Determine diagram type based on graph type
        if graph.metadata.get("graph_type") == "service_dependencies":
            lines.append("graph TD")
        else:
            lines.append("graph LR")

        # Add style definitions
        lines.extend(
            [
                "    classDef critical fill:#ff6b6b,stroke:#d63031,stroke-width:3px",
                "    classDef important fill:#ffa726,stroke:#ef6c00,stroke-width:2px",
                "    classDef medium fill:#42a5f5,stroke:#1565c0,stroke-width:2px",
                "    classDef low fill:#66bb6a,stroke:#2e7d32,stroke-width:1px",
            ]
        )

        # Add nodes
        for node in graph.nodes:
            node_id = node.id.replace("-", "_").replace(".", "_")
            node_label = node.label.replace('"', '\\"')

            # Shape based on node type
            if node.node_type == "service":
                shape = f"{node_id}[{node_label}]"
            elif node.node_type == "database":
                shape = f"{node_id}[(({node_label})))"
            elif node.node_type == "cache":
                shape = f"{node_id}[/{node_label}/]"
            elif node.node_type == "endpoint":
                shape = f"{node_id}{{/{node_label}/}}"
            else:
                shape = f"{node_id}({node_label})"

            lines.append(f"    {shape}")

            # Apply styling based on criticality
            if node.criticality in ["critical", "important", "medium", "low"]:
                lines.append(f"    class {node_id} {node.criticality}")

        # Add edges
        for edge in graph.edges:
            source_id = edge.source.replace("-", "_").replace(".", "_")
            target_id = edge.target.replace("-", "_").replace(".", "_")

            # Arrow style based on edge type
            if edge.edge_type == "service_dependency":
                arrow = "-->|depends on|"
            elif edge.edge_type == "uses_repository":
                arrow = "-->|uses|"
            elif edge.edge_type == "foreign_key":
                arrow = "-.->|FK|"
            elif edge.edge_type == "many_to_many":
                arrow = "<-->|M2M|"
            else:
                arrow = "-->"

            lines.append(f"    {source_id} {arrow} {target_id}")

        diagram = "\n".join(lines)

        logger.info("Mermaid diagram generated", lines_count=len(lines))
        return diagram

    def generate_dot_graph(self, graph: DependencyGraph) -> str:
        """Generate DOT format graph for Graphviz."""
        logger.info("Generating DOT graph", graph_type=graph.metadata.get("graph_type"))

        lines = []

        # Graph header
        graph_type = "digraph"  # Always use directed graph
        graph_name = graph.metadata.get("graph_type", "dependency_graph").replace(" ", "_")
        lines.append(f"{graph_type} {graph_name} {{")
        lines.append("  rankdir=LR;")
        lines.append("  node [shape=box, style=rounded];")

        # Node definitions
        for node in graph.nodes:
            node_id = node.id.replace("-", "_").replace(".", "_")
            node_label = node.label.replace('"', '\\"')

            # Color based on criticality
            color_map = {"critical": "red", "important": "orange", "medium": "blue", "low": "green"}
            color = color_map.get(node.criticality, "gray")

            # Shape based on node type
            shape_map = {
                "service": "box",
                "database": "cylinder",
                "cache": "diamond",
                "endpoint": "hexagon",
                "repository": "ellipse",
                "middleware": "octagon",
            }
            shape = shape_map.get(node.node_type, "box")

            lines.append(f'  {node_id} [label="{node_label}", color={color}, shape={shape}];')

        # Edge definitions
        for edge in graph.edges:
            source_id = edge.source.replace("-", "_").replace(".", "_")
            target_id = edge.target.replace("-", "_").replace(".", "_")

            # Style based on edge type
            style_map = {
                "service_dependency": "solid",
                "uses_repository": "dashed",
                "foreign_key": "dotted",
                "many_to_many": "bold",
            }
            style = style_map.get(edge.edge_type, "solid")

            lines.append(f'  {source_id} -> {target_id} [style={style}, label="{edge.edge_type}"];')

        lines.append("}")

        dot_graph = "\n".join(lines)

        logger.info("DOT graph generated", lines_count=len(lines))
        return dot_graph

    def generate_plantuml_diagram(self, graph: DependencyGraph) -> str:
        """Generate PlantUML diagram from dependency graph."""
        logger.info("Generating PlantUML diagram", graph_type=graph.metadata.get("graph_type"))

        lines = []

        # PlantUML header
        lines.append("@startuml")
        lines.append("!define RECTANGLE class")
        lines.append("skinparam linetype ortho")

        # Add styling
        lines.extend(
            [
                "skinparam class {",
                "  BackgroundColor<<critical>> LightPink",
                "  BackgroundColor<<important>> LightOrange",
                "  BackgroundColor<<medium>> LightBlue",
                "  BackgroundColor<<low>> LightGreen",
                "}",
            ]
        )

        # Add nodes
        for node in graph.nodes:
            node_id = node.id.replace("-", "_").replace(".", "_")
            node_label = node.label
            stereotype = f"<<{node.criticality}>>"

            if node.node_type == "database":
                lines.append(f'database {node_id} as "{node_label}" {stereotype}')
            elif node.node_type == "cache":
                lines.append(f'cloud {node_id} as "{node_label}" {stereotype}')
            elif node.node_type == "service":
                lines.append(f'rectangle {node_id} as "{node_label}" {stereotype}')
            else:
                lines.append(f'class {node_id} as "{node_label}" {stereotype}')

        # Add relationships
        for edge in graph.edges:
            source_id = edge.source.replace("-", "_").replace(".", "_")
            target_id = edge.target.replace("-", "_").replace(".", "_")

            # Arrow style based on edge type
            if edge.edge_type == "service_dependency":
                arrow = "-->"
            elif edge.edge_type == "uses_repository":
                arrow = "..>"
            elif edge.edge_type == "foreign_key":
                arrow = "||--||"
            elif edge.edge_type == "many_to_many":
                arrow = "}--{"
            else:
                arrow = "-->"

            lines.append(f"{source_id} {arrow} {target_id} : {edge.edge_type}")

        lines.append("@enduml")

        plantuml_diagram = "\n".join(lines)

        logger.info("PlantUML diagram generated", lines_count=len(lines))
        return plantuml_diagram

    def export_to_formats(self, graph: DependencyGraph, output_dir: str, base_name: str) -> Dict[str, str]:
        """Export graphs to multiple formats."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        exported_files = {}

        try:
            # Export JSON format
            json_file = output_path / f"{base_name}.json"
            with open(json_file, "w") as f:
                graph_dict = {
                    "metadata": graph.metadata,
                    "nodes": [
                        {
                            "id": node.id,
                            "label": node.label,
                            "type": node.node_type,
                            "criticality": node.criticality,
                            "properties": node.properties,
                        }
                        for node in graph.nodes
                    ],
                    "edges": [
                        {
                            "source": edge.source,
                            "target": edge.target,
                            "type": edge.edge_type,
                            "properties": edge.properties,
                        }
                        for edge in graph.edges
                    ],
                }
                json.dump(graph_dict, f, indent=2)
            exported_files["json"] = str(json_file)

            # Export Mermaid format
            mermaid_file = output_path / f"{base_name}.mmd"
            with open(mermaid_file, "w") as f:
                f.write(self.generate_mermaid_diagram(graph))
            exported_files["mermaid"] = str(mermaid_file)

            # Export DOT format
            dot_file = output_path / f"{base_name}.dot"
            with open(dot_file, "w") as f:
                f.write(self.generate_dot_graph(graph))
            exported_files["dot"] = str(dot_file)

            # Export PlantUML format
            plantuml_file = output_path / f"{base_name}.puml"
            with open(plantuml_file, "w") as f:
                f.write(self.generate_plantuml_diagram(graph))
            exported_files["plantuml"] = str(plantuml_file)

            logger.info(
                "Graph exported to multiple formats", output_dir=output_dir, formats=list(exported_files.keys())
            )

        except Exception as e:
            logger.error("Error exporting graph", error=str(e))
            raise

        return exported_files

    def generate_combined_graph(
        self, service_graph: DependencyGraph, application_graph: DependencyGraph, database_graph: DependencyGraph
    ) -> DependencyGraph:
        """Generate a combined multi-layer dependency graph."""
        logger.info("Generating combined dependency graph")

        # Combine all nodes and edges
        all_nodes = service_graph.nodes + application_graph.nodes + database_graph.nodes

        all_edges = service_graph.edges + application_graph.edges + database_graph.edges

        # Remove duplicate nodes (by id)
        unique_nodes = {}
        for node in all_nodes:
            if node.id not in unique_nodes:
                unique_nodes[node.id] = node

        # Remove duplicate edges
        unique_edges = {}
        for edge in all_edges:
            edge_key = f"{edge.source}->{edge.target}:{edge.edge_type}"
            if edge_key not in unique_edges:
                unique_edges[edge_key] = edge

        combined_graph = DependencyGraph(
            nodes=list(unique_nodes.values()),
            edges=list(unique_edges.values()),
            metadata={
                "graph_type": "combined_dependencies",
                "generated_at": datetime.now().isoformat(),
                "total_nodes": len(unique_nodes),
                "total_edges": len(unique_edges),
                "source_graphs": ["service", "application", "database"],
            },
        )

        self.graphs["combined"] = combined_graph
        logger.info("Combined dependency graph generated", nodes=len(unique_nodes), edges=len(unique_edges))

        return combined_graph


def main():
    """Main entry point for standalone execution."""
    import sys

    if len(sys.argv) < 3:
        print("Usage: python graph_generator.py <input_analysis_file> <output_dir>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_dir = sys.argv[2]

    # Load analysis data
    with open(input_file, "r") as f:
        analysis_data = json.load(f)

    generator = DependencyGraphGenerator()

    # Generate service graph
    if "service_dependencies" in analysis_data:
        service_graph = generator.generate_service_graph(analysis_data["service_dependencies"])
        generator.export_to_formats(service_graph, output_dir, "service_dependencies")

    # Generate application graph (if data is available)
    # This would require additional endpoint and middleware data

    print(f"Dependency graphs generated and saved to {output_dir}")


if __name__ == "__main__":
    main()
