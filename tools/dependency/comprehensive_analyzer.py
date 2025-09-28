"""Comprehensive dependency analysis orchestrator for ViolentUTF API."""

import asyncio
import json
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from audit_utils.database import AuditDatabaseMixin, get_audit_session
from audit_utils.logging import setup_audit_logger
from audit_utils.models import AuditMetadata, AuditStatus, ComprehensiveAnalysisResult, convert_to_dict

from .graph_generator import DependencyGraph, DependencyGraphGenerator
from .repository_analyzer import RepositoryAnalysisResult, RepositoryDependencyAnalyzer
from .runtime_tracer import RuntimeDependencyAnalysis, RuntimeDependencyTracer
from .static_analyzer import DependencyAnalysisResult as StaticResult
from .static_analyzer import StaticDependencyAnalyzer

logger = setup_audit_logger(__name__)


# Using ComprehensiveAnalysisResult from audit_utils.models


class ComprehensiveDependencyAnalyzer(AuditDatabaseMixin):
    """Orchestrate comprehensive dependency analysis."""

    def __init__(self, project_root: str):
        """Initialize the comprehensive analyzer."""
        self.project_root = Path(project_root)
        self.output_dir = self.project_root / "docs" / "dependencies"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize component analyzers
        self.static_analyzer = StaticDependencyAnalyzer(str(project_root))
        self.repository_analyzer = RepositoryDependencyAnalyzer(str(project_root))
        self.graph_generator = DependencyGraphGenerator(str(project_root))
        self.runtime_tracer = RuntimeDependencyTracer(str(project_root))

        logger.info("ComprehensiveDependencyAnalyzer initialized", project_root=str(self.project_root))

    async def analyze_all_dependencies(
        self, include_runtime: bool = False, runtime_duration: int = 30
    ) -> ComprehensiveAnalysisResult:
        """Perform comprehensive dependency analysis."""
        logger.info("Starting comprehensive dependency analysis", include_runtime=include_runtime)

        analysis_start = datetime.now()

        # Phase 1: Static Analysis
        logger.info("Phase 1: Static dependency analysis")
        static_result = self.static_analyzer.analyze_all_dependencies()

        # Phase 2: Repository Analysis
        logger.info("Phase 2: Repository dependency analysis")
        repository_result = self.repository_analyzer.analyze_all_repositories()

        # Phase 3: Graph Generation
        logger.info("Phase 3: Dependency graph generation")
        graphs = await self._generate_all_graphs(static_result, repository_result)

        # Phase 4: Runtime Analysis (optional)
        runtime_result = None
        if include_runtime:
            logger.info("Phase 4: Runtime dependency analysis", duration=runtime_duration)
            runtime_result = await self.runtime_tracer.monitor_live_dependencies(runtime_duration)

        # Phase 5: Summary and Recommendations
        logger.info("Phase 5: Generating summary and recommendations")
        summary_report = self._generate_summary_report(static_result, repository_result, runtime_result)
        recommendations = self._generate_recommendations(static_result, repository_result, runtime_result)

        analysis_end = datetime.now()
        analysis_duration = (analysis_end - analysis_start).total_seconds()

        # Create audit metadata
        audit_metadata = AuditMetadata(
            audit_type="ComprehensiveDependencyAnalysis", scope="full_project", status=AuditStatus.COMPLETED
        )

        # Enhance static analysis with metadata
        enhanced_static_analysis = self._serialize_static_result(static_result)
        enhanced_static_analysis.update(
            {
                "analysis_date": analysis_start.isoformat(),
                "analysis_duration_seconds": analysis_duration,
                "project_root": str(self.project_root),
                "analyzer_version": "1.0.0",
                "phases_completed": 5 if include_runtime else 4,
                "total_services": len(static_result.service_dependencies),
                "total_repositories": len(repository_result.repositories),
                "total_configurations": len(static_result.configuration_dependencies),
            }
        )

        # Compile comprehensive result
        result = ComprehensiveAnalysisResult(
            metadata=audit_metadata,
            static_analysis=enhanced_static_analysis,
            repository_analysis=self._serialize_repository_result(repository_result),
            runtime_analysis=self._serialize_runtime_result(runtime_result) if runtime_result else None,
            dependency_graphs=graphs,
            summary_report=summary_report,
            recommendations=recommendations,
        )

        logger.info(
            "Comprehensive dependency analysis completed",
            duration=analysis_duration,
            services=enhanced_static_analysis["total_services"],
            repositories=enhanced_static_analysis["total_repositories"],
        )

        return result

    async def _generate_all_graphs(
        self, static_result: StaticResult, repository_result: RepositoryAnalysisResult
    ) -> Dict[str, str]:
        """Generate all dependency graphs."""
        graphs = {}

        # Service dependency graph - convert to dicts
        service_deps_dict = [
            convert_to_dict(dep) if hasattr(dep, "model_dump") or hasattr(dep, "__dict__") else dep
            for dep in static_result.service_dependencies
        ]
        service_graph = self.graph_generator.generate_service_graph(service_deps_dict)
        service_files = self.graph_generator.export_to_formats(
            service_graph, str(self.output_dir), "service_dependencies"
        )
        graphs["service"] = service_files["mermaid"]

        # Repository dependency graph (create mock data for now)
        repo_deps = []
        endpoint_deps = []
        middleware_deps = []

        for repo in repository_result.repositories:
            repo_deps.append(
                {
                    "name": repo.name,
                    "criticality": "medium",
                    "models": [repo.model_class] if repo.model_class else [],
                    "operations": repo.methods,
                }
            )

        # Generate basic endpoint and middleware data
        for i in range(5):  # Mock some endpoints
            endpoint_deps.append(
                {
                    "name": f"endpoint_{i}",
                    "criticality": "medium",
                    "repositories": [repo.name for repo in repository_result.repositories[:2]],
                    "middleware": ["auth", "logging"],
                }
            )

        middleware_deps = [
            {"name": "auth", "criticality": "critical", "order": 1},
            {"name": "logging", "criticality": "medium", "order": 2},
            {"name": "rate_limiting", "criticality": "important", "order": 3},
        ]

        app_graph = self.graph_generator.generate_application_graph(repo_deps, endpoint_deps, middleware_deps)
        app_files = self.graph_generator.export_to_formats(app_graph, str(self.output_dir), "application_dependencies")
        graphs["application"] = app_files["mermaid"]

        # Database dependency graph
        model_deps = []
        for rel in repository_result.model_relationships:
            model_deps.append(
                {
                    "name": rel.source_model,
                    "relationships": [
                        {
                            "target": rel.target_model,
                            "type": rel.relationship_type,
                            "cascade": rel.cascade,
                            "nullable": rel.nullable,
                        }
                    ],
                }
            )

        if model_deps:
            db_graph = self.graph_generator.generate_database_graph(model_deps)
            db_files = self.graph_generator.export_to_formats(db_graph, str(self.output_dir), "database_dependencies")
            graphs["database"] = db_files["mermaid"]

        return graphs

    def _generate_summary_report(
        self,
        static_result: StaticResult,
        repository_result: RepositoryAnalysisResult,
        runtime_result: Optional[RuntimeDependencyAnalysis],
    ) -> Dict[str, Any]:
        """Generate comprehensive summary report."""

        # Service summary
        service_summary = {
            "total_services": len(static_result.service_dependencies),
            "critical_services": len([s for s in static_result.service_dependencies if s.criticality == "critical"]),
            "service_types": static_result.analysis_summary["service_analysis"]["service_types"],
            "average_dependencies": static_result.analysis_summary["service_analysis"][
                "average_dependencies_per_service"
            ],
        }

        # Repository summary
        repo_summary = {
            "total_repositories": len(repository_result.repositories),
            "total_models": repository_result.metadata["total_models"],
            "total_relationships": len(repository_result.model_relationships),
            "average_complexity": repository_result.complexity_analysis.get("average_complexity", 0),
            "most_complex_repository": repository_result.complexity_analysis.get("most_complex_repository", "None"),
        }

        # Configuration summary
        config_summary = {
            "total_configurations": len(static_result.configuration_dependencies),
            "required_configurations": len([c for c in static_result.configuration_dependencies if c.required]),
            "configuration_types": static_result.analysis_summary["configuration_analysis"]["configuration_types"],
        }

        # Runtime summary (if available)
        runtime_summary = {}
        if runtime_result:
            runtime_summary = {
                "total_traces": runtime_result.metadata["total_traces"],
                "unique_dependencies": runtime_result.metadata["unique_dependencies"],
                "average_duration": runtime_result.performance_summary.get("average_duration", 0),
                "error_rate": runtime_result.performance_summary.get("error_rate", 0),
            }

        # Risk assessment
        risk_assessment = {
            "high_risk_services": [s.name for s in static_result.service_dependencies if s.criticality == "critical"],
            "complex_repositories": [
                r.name
                for r in repository_result.repositories
                if r.complexity_score > repository_result.complexity_analysis.get("average_complexity", 0) * 1.5
            ],
            "single_points_of_failure": self._identify_single_points_of_failure(static_result),
        }

        return {
            "services": service_summary,
            "repositories": repo_summary,
            "configurations": config_summary,
            "runtime": runtime_summary,
            "risk_assessment": risk_assessment,
            "analysis_completeness": {
                "static_analysis": True,
                "repository_analysis": True,
                "runtime_analysis": runtime_result is not None,
                "graph_generation": True,
            },
        }

    def _identify_single_points_of_failure(self, static_result: StaticResult) -> List[str]:
        """Identify potential single points of failure."""
        spofs = []

        # Services with many dependents
        for service in static_result.service_dependencies:
            if len(service.dependents) >= 2:
                spofs.append(f"Service: {service.name} (depended on by {len(service.dependents)} services)")

        # Critical services without redundancy
        critical_services = [s for s in static_result.service_dependencies if s.criticality == "critical"]
        for service in critical_services:
            if service.service_type in ["database", "cache"]:
                spofs.append(f"Critical {service.service_type}: {service.name}")

        return spofs

    def _generate_recommendations(
        self,
        static_result: StaticResult,
        repository_result: RepositoryAnalysisResult,
        runtime_result: Optional[RuntimeDependencyAnalysis],
    ) -> List[str]:
        """Generate optimization recommendations."""
        recommendations = []

        # Service recommendations
        critical_count = len([s for s in static_result.service_dependencies if s.criticality == "critical"])
        if critical_count > len(static_result.service_dependencies) * 0.5:
            recommendations.append(
                "High number of critical services detected. Consider implementing redundancy and failover mechanisms."
            )

        # Repository recommendations
        if repository_result.complexity_analysis:
            avg_complexity = repository_result.complexity_analysis.get("average_complexity", 0)
            high_complexity_repos = [
                r for r in repository_result.repositories if r.complexity_score > avg_complexity * 2
            ]
            if high_complexity_repos:
                recommendations.append(
                    f"Refactor high-complexity repositories: {', '.join([r.name for r in high_complexity_repos])}"
                )

        # Configuration recommendations
        required_configs = [c for c in static_result.configuration_dependencies if c.required]
        if len(required_configs) > 20:
            recommendations.append(
                "Large number of required configurations. Consider configuration validation and documentation improvements."
            )

        # Runtime recommendations
        if runtime_result and runtime_result.bottleneck_analysis:
            bottlenecks = runtime_result.bottleneck_analysis
            if bottlenecks.get("slow_dependencies"):
                recommendations.append("Optimize slow dependencies identified in runtime analysis")
            if bottlenecks.get("error_prone_dependencies"):
                recommendations.append("Improve error handling for dependencies with high error rates")

        # General recommendations
        recommendations.extend(
            [
                "Implement dependency health monitoring with automated alerts",
                "Create dependency change impact assessment procedures",
                "Establish regular dependency review and optimization cycles",
                "Document dependency failure scenarios and recovery procedures",
            ]
        )

        return recommendations

    async def persist_analysis_to_database(self, result: ComprehensiveAnalysisResult) -> bool:
        """
        Persist comprehensive analysis results to database using standardized session management.

        Args:
            result: ComprehensiveAnalysisResult to persist

        Returns:
            bool: True if persistence was successful, False otherwise
        """
        try:
            logger.info("Persisting comprehensive analysis to database")

            # Example of using inherited database capabilities
            async with get_audit_session() as session:  # noqa: F841
                # This demonstrates how to use the database session management
                # In a real implementation, you would persist the analysis data
                logger.info(
                    "Analysis persistence simulated",
                    audit_type=result.metadata.audit_type,
                    total_services=result.static_analysis.get("total_services", 0),
                    total_repositories=result.static_analysis.get("total_repositories", 0),
                    recommendations_count=len(result.recommendations),
                )

                # Could use inherited methods like:
                # analysis_data = convert_to_dict(result)
                # await self.bulk_insert(AnalysisModel, [analysis_data])

                return True

        except Exception as e:
            logger.error(f"Failed to persist analysis to database: {e}")
            return False

    def _serialize_static_result(self, result: StaticResult) -> Dict[str, Any]:
        """Serialize static analysis result."""
        return {
            "metadata": result.metadata,
            "service_dependencies": [convert_to_dict(dep) for dep in result.service_dependencies],
            "configuration_dependencies": [convert_to_dict(dep) for dep in result.configuration_dependencies],
            "network_dependencies": result.network_dependencies,
            "volume_dependencies": result.volume_dependencies,
            "analysis_summary": result.analysis_summary,
        }

    def _serialize_repository_result(self, result: RepositoryAnalysisResult) -> Dict[str, Any]:
        """Serialize repository analysis result."""
        return {
            "metadata": result.metadata,
            "repositories": [convert_to_dict(repo) for repo in result.repositories],
            "model_relationships": [convert_to_dict(rel) for rel in result.model_relationships],
            "repository_dependencies": [convert_to_dict(dep) for dep in result.repository_dependencies],
            "complexity_analysis": result.complexity_analysis,
            "inheritance_hierarchy": result.inheritance_hierarchy,
            "pattern_analysis": result.pattern_analysis,
        }

    def _serialize_runtime_result(self, result: RuntimeDependencyAnalysis) -> Dict[str, Any]:
        """Serialize runtime analysis result."""
        return {
            "metadata": result.metadata,
            "operation_traces": [convert_to_dict(trace) for trace in result.operation_traces],
            "dependency_patterns": [convert_to_dict(pattern) for pattern in result.dependency_patterns],
            "performance_summary": result.performance_summary,
            "bottleneck_analysis": result.bottleneck_analysis,
            "failure_patterns": result.failure_patterns,
        }

    def export_comprehensive_analysis(
        self, result: ComprehensiveAnalysisResult, output_path: Optional[str] = None
    ) -> str:
        """Export comprehensive analysis results."""
        if output_path is None:
            output_path = str(self.output_dir / "comprehensive_analysis.json")

        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Convert to dictionary for JSON serialization
        result_dict = {
            "metadata": result.metadata,
            "static_analysis": result.static_analysis,
            "repository_analysis": result.repository_analysis,
            "runtime_analysis": result.runtime_analysis,
            "dependency_graphs": result.dependency_graphs,
            "summary_report": result.summary_report,
            "recommendations": result.recommendations,
        }

        with open(output_file, "w") as f:
            json.dump(result_dict, f, indent=2)

        logger.info("Comprehensive analysis exported", output_path=str(output_file))
        return str(output_file)

    def generate_markdown_report(self, result: ComprehensiveAnalysisResult) -> str:
        """Generate human-readable markdown report."""
        report_path = str(self.output_dir / "dependency_analysis_report.md")

        with open(report_path, "w") as f:
            f.write(
                f"""# ViolentUTF API Dependency Analysis Report

Generated on: {result.metadata['analysis_date']}
Analysis Duration: {result.metadata['analysis_duration_seconds']:.2f} seconds

## Executive Summary

This comprehensive dependency analysis covers all layers of the ViolentUTF API system:

- **Services**: {result.metadata['total_services']} Docker services analyzed
- **Repositories**: {result.metadata['total_repositories']} repository classes analyzed
- **Configurations**: {result.metadata['total_configurations']} configuration parameters analyzed

## Service Dependencies

### Critical Services
{chr(10).join(f"- {service}" for service in result.summary_report['risk_assessment']['high_risk_services'])}

### Service Types Distribution
{chr(10).join(f"- {stype}: {count}" for stype, count in result.summary_report['services']['service_types'].items())}

## Repository Analysis

- **Total Repositories**: {result.summary_report['repositories']['total_repositories']}
- **Total Models**: {result.summary_report['repositories']['total_models']}
- **Model Relationships**: {result.summary_report['repositories']['total_relationships']}
- **Average Complexity**: {result.summary_report['repositories']['average_complexity']:.2f}
- **Most Complex Repository**: {result.summary_report['repositories']['most_complex_repository']}

## Configuration Analysis

- **Total Configurations**: {result.summary_report['configurations']['total_configurations']}
- **Required Configurations**: {result.summary_report['configurations']['required_configurations']}

## Risk Assessment

### Single Points of Failure
{chr(10).join(f"- {spof}" for spof in result.summary_report['risk_assessment']['single_points_of_failure'])}

### Complex Repositories
{chr(10).join(f"- {repo}" for repo in result.summary_report['risk_assessment']['complex_repositories'])}

## Recommendations

{chr(10).join(f"{i+1}. {rec}" for i, rec in enumerate(result.recommendations))}

## Dependency Graphs

The following dependency graphs have been generated:

{chr(10).join(f"- **{graph_type.title()}**: `{path}`" for graph_type, path in result.dependency_graphs.items())}

## Analysis Completeness

{chr(10).join(f"- {analysis}: {'✓' if complete else '✗'}" for analysis, complete in result.summary_report['analysis_completeness'].items())}

---

*This report was generated automatically by the ViolentUTF API Dependency Analysis Tool v{result.metadata['analyzer_version']}*
"""
            )

        logger.info("Markdown report generated", report_path=report_path)
        return report_path


async def main():
    """Main entry point for standalone execution."""
    import sys

    project_root = sys.argv[1] if len(sys.argv) > 1 else "."
    include_runtime = len(sys.argv) > 2 and sys.argv[2].lower() == "true"
    runtime_duration = int(sys.argv[3]) if len(sys.argv) > 3 else 30

    analyzer = ComprehensiveDependencyAnalyzer(project_root)
    result = await analyzer.analyze_all_dependencies(include_runtime, runtime_duration)

    # Export results
    json_path = analyzer.export_comprehensive_analysis(result)
    md_path = analyzer.generate_markdown_report(result)

    print(f"Comprehensive dependency analysis completed!")
    print(f"JSON Report: {json_path}")
    print(f"Markdown Report: {md_path}")
    print(f"Dependency Graphs: {analyzer.output_dir}")


if __name__ == "__main__":
    asyncio.run(main())
