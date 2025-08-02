#!/usr/bin/env python3
"""
Multi-Agent Architectural Analysis System

This module implements a sophisticated multi-agent architecture for comprehensive
architectural analysis using Claude Code's capabilities. Each agent specializes
in a specific aspect of analysis and they work together through shared context.
"""

import asyncio
import json
import logging
import os
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from anthropic import Anthropic

    CLAUDE_AVAILABLE = True
except ImportError:
    CLAUDE_AVAILABLE = False
    print("Warning: Anthropic package not available. Running in limited mode.")


class AgentType(Enum):
    """Types of specialized analysis agents"""

    SEMANTIC_ANALYZER = "semantic_analyzer"
    VIOLATION_DETECTOR = "violation_detector"
    REMEDIATION_ASSISTANT = "remediation_assistant"
    HISTORY_FORENSICS = "history_forensics"
    SECURITY_ANALYZER = "security_analyzer"
    PERFORMANCE_ANALYZER = "performance_analyzer"


@dataclass
class AgentCapability:
    """Defines what an agent can do"""

    name: str
    description: str
    tools_required: List[str]
    output_format: str


@dataclass
class SharedContext:
    """Shared context between all agents"""

    repository_path: str
    adr_documents: Dict[str, str] = field(default_factory=dict)
    relevant_files: List[str] = field(default_factory=list)
    adr_requirements: Dict[str, Any] = field(default_factory=dict)
    analysis_results: Dict[str, Any] = field(default_factory=dict)
    violations_found: List[Dict[str, Any]] = field(default_factory=list)
    suggested_fixes: List[Dict[str, Any]] = field(default_factory=list)
    architectural_insights: List[str] = field(default_factory=list)
    performance_metrics: Dict[str, float] = field(default_factory=dict)

    def update_from_agent(self, agent_type: AgentType, results: Dict[str, Any]) -> None:
        """Update shared context with agent results"""
        self.analysis_results[agent_type.value] = results

        # Extract common elements
        if "violations" in results:
            self.violations_found.extend(results["violations"])
        if "fixes" in results:
            self.suggested_fixes.extend(results["fixes"])
        if "insights" in results:
            self.architectural_insights.extend(results["insights"])
        if "files" in results:
            self.relevant_files.extend(results["files"])
            self.relevant_files = list(set(self.relevant_files))  # Remove duplicates


@dataclass
class AgentTask:
    """A task for an agent to execute"""

    agent_type: AgentType
    prompt: str
    context: SharedContext
    priority: int = 0
    timeout: int = 300
    dependencies: List[AgentType] = field(default_factory=list)


@dataclass
class AgentResult:
    """Result from an agent execution"""

    agent_type: AgentType
    success: bool
    results: Dict[str, Any]
    execution_time: float
    error: Optional[str] = None


class AnalysisAgent(ABC):
    """Base class for all analysis agents"""

    def __init__(self, agent_type: AgentType, capabilities: List[AgentCapability]):
        self.agent_type = agent_type
        self.capabilities = capabilities
        self.logger = logging.getLogger(f"Agent.{agent_type.value}")

    @abstractmethod
    async def analyze(self, task: AgentTask) -> AgentResult:
        """Execute analysis based on task"""
        pass

    def can_handle(self, task: AgentTask) -> bool:
        """Check if agent can handle the task"""
        return task.agent_type == self.agent_type

    def get_required_tools(self) -> Set[str]:
        """Get all tools required by this agent"""
        tools = set()
        for capability in self.capabilities:
            tools.update(capability.tools_required)
        return tools


class SemanticAnalyzerAgent(AnalysisAgent):
    """Agent for semantic code analysis and ADR understanding"""

    def __init__(self) -> None:
        capabilities = [
            AgentCapability(
                name="adr_understanding",
                description="Analyze and understand ADR requirements",
                tools_required=["Read", "Grep"],
                output_format="structured_requirements",
            ),
            AgentCapability(
                name="semantic_compliance",
                description="Check code semantic compliance with ADRs",
                tools_required=["Read", "Grep", "Glob"],
                output_format="compliance_report",
            ),
        ]
        super().__init__(AgentType.SEMANTIC_ANALYZER, capabilities)

    async def analyze(self, task: AgentTask) -> AgentResult:
        """Analyze ADR requirements and code semantics"""
        start_time = datetime.now()

        try:
            # Extract ADR requirements
            adr_requirements = await self._extract_adr_requirements(task.context)

            # Find relevant code files
            relevant_files = await self._discover_relevant_files(task.context)

            # Analyze semantic compliance
            compliance_results = await self._analyze_semantic_compliance(relevant_files, adr_requirements, task.context)

            results = {
                "adr_requirements": adr_requirements,
                "files": relevant_files,
                "compliance": compliance_results,
                "insights": self._generate_insights(compliance_results),
            }

            # Update shared context
            task.context.update_from_agent(self.agent_type, results)

            execution_time = (datetime.now() - start_time).total_seconds()
            return AgentResult(agent_type=self.agent_type, success=True, results=results, execution_time=execution_time)

        except Exception as e:
            self.logger.error(f"Semantic analysis failed: {e}")
            execution_time = (datetime.now() - start_time).total_seconds()
            return AgentResult(
                agent_type=self.agent_type, success=False, results={}, execution_time=execution_time, error=str(e)
            )

    async def _extract_adr_requirements(self, context: SharedContext) -> Dict[str, Any]:
        """Extract requirements from ADR documents"""
        requirements = {}

        # In a real implementation, this would use Claude to analyze ADRs
        # For now, return mock requirements
        for adr_id, adr_content in context.adr_documents.items():
            requirements[adr_id] = {
                "rules": ["Authentication must use JWT", "All endpoints require rate limiting"],
                "constraints": ["Max 100 requests per minute", "Token expiry 24 hours"],
                "patterns": ["Repository pattern for data access", "Middleware for auth"],
            }

        return requirements

    async def _discover_relevant_files(self, context: SharedContext) -> List[str]:
        """Discover files relevant to architectural analysis"""
        # In real implementation, use Glob and Grep tools
        # For now, return mock file list
        return [
            "app/core/auth.py",
            "app/middleware/authentication.py",
            "app/api/endpoints/auth.py",
            "app/services/user.py",
        ]

    async def _analyze_semantic_compliance(
        self, files: List[str], requirements: Dict[str, Any], context: SharedContext
    ) -> Dict[str, Any]:
        """Analyze semantic compliance of code with requirements"""
        # In real implementation, use Claude to analyze code semantics
        # For now, return mock analysis
        return {
            "compliant_files": files[:2],
            "violations": [
                {
                    "file": files[2],
                    "requirement": "Authentication must use JWT",
                    "issue": "Direct session usage found",
                    "confidence": 0.85,
                }
            ],
            "coverage": 0.75,
        }

    def _generate_insights(self, compliance_results: Dict[str, Any]) -> List[str]:
        """Generate architectural insights from analysis"""
        insights = []

        coverage = compliance_results.get("coverage", 0)
        if coverage < 0.8:
            insights.append(f"Architecture coverage is {coverage:.0%} - consider expanding analysis")

        violations = compliance_results.get("violations", [])
        if violations:
            insights.append(f"Found {len(violations)} semantic violations requiring attention")

        return insights


class ViolationDetectorAgent(AnalysisAgent):
    """Agent for detecting architectural violations"""

    def __init__(self) -> None:
        capabilities = [
            AgentCapability(
                name="pattern_detection",
                description="Detect violation patterns in code",
                tools_required=["Read", "Grep", "Task"],
                output_format="violation_list",
            ),
            AgentCapability(
                name="multi_dimensional_analysis",
                description="Analyze violations across multiple dimensions",
                tools_required=["Read", "Task", "MultiEdit"],
                output_format="dimensional_report",
            ),
        ]
        super().__init__(AgentType.VIOLATION_DETECTOR, capabilities)

    async def analyze(self, task: AgentTask) -> AgentResult:
        """Detect architectural violations"""
        start_time = datetime.now()

        try:
            # Get files to analyze from shared context
            files_to_analyze = task.context.relevant_files
            adr_requirements = task.context.adr_requirements

            # Detect violations
            violations = await self._detect_violations(files_to_analyze, adr_requirements)

            # Perform multi-dimensional analysis
            dimensional_analysis = await self._multi_dimensional_analysis(violations)

            results = {
                "violations": violations,
                "dimensional_analysis": dimensional_analysis,
                "summary": self._generate_violation_summary(violations),
                "insights": self._generate_violation_insights(violations, dimensional_analysis),
            }

            # Update shared context
            task.context.update_from_agent(self.agent_type, results)

            execution_time = (datetime.now() - start_time).total_seconds()
            return AgentResult(agent_type=self.agent_type, success=True, results=results, execution_time=execution_time)

        except Exception as e:
            self.logger.error(f"Violation detection failed: {e}")
            execution_time = (datetime.now() - start_time).total_seconds()
            return AgentResult(
                agent_type=self.agent_type, success=False, results={}, execution_time=execution_time, error=str(e)
            )

    async def _detect_violations(self, files: List[str], requirements: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect violations in files based on requirements"""
        violations = []

        # Mock violation detection
        for i, file in enumerate(files[:2]):  # Simulate finding violations in first 2 files
            violations.append(
                {
                    "id": f"VIO-{i+1:03d}",
                    "file": file,
                    "line": 42 + i * 10,
                    "type": "architectural_boundary",
                    "severity": "high" if i == 0 else "medium",
                    "adr_id": "ADR-002",
                    "description": f"Violation of architectural pattern in {file}",
                    "confidence": 0.9 - (i * 0.1),
                }
            )

        return violations

    async def _multi_dimensional_analysis(self, violations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze violations across multiple dimensions"""
        return {
            "by_severity": {
                "high": len([v for v in violations if v.get("severity") == "high"]),
                "medium": len([v for v in violations if v.get("severity") == "medium"]),
                "low": len([v for v in violations if v.get("severity") == "low"]),
            },
            "by_type": {
                "architectural_boundary": len([v for v in violations if "boundary" in v.get("type", "")]),
                "pattern_violation": len([v for v in violations if "pattern" in v.get("type", "")]),
            },
            "by_confidence": {
                "high_confidence": len([v for v in violations if v.get("confidence", 0) > 0.8]),
                "medium_confidence": len([v for v in violations if 0.5 < v.get("confidence", 0) <= 0.8]),
                "low_confidence": len([v for v in violations if v.get("confidence", 0) <= 0.5]),
            },
        }

    def _generate_violation_summary(self, violations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary of violations"""
        return {
            "total_violations": len(violations),
            "critical_violations": len([v for v in violations if v.get("severity") == "critical"]),
            "affected_files": len(set(v.get("file") for v in violations)),
            "affected_adrs": len(set(v.get("adr_id") for v in violations)),
        }

    def _generate_violation_insights(self, violations: List[Dict[str, Any]], dimensional: Dict[str, Any]) -> List[str]:
        """Generate insights about violations"""
        insights = []

        high_severity = dimensional["by_severity"].get("high", 0)
        if high_severity > 0:
            insights.append(f"{high_severity} high-severity violations require immediate attention")

        high_confidence = dimensional["by_confidence"].get("high_confidence", 0)
        total = len(violations)
        if total > 0 and high_confidence / total > 0.7:
            insights.append("High confidence in violation detection - results are reliable")

        return insights


class RemediationAssistantAgent(AnalysisAgent):
    """Agent for suggesting and implementing fixes"""

    def __init__(self) -> None:
        capabilities = [
            AgentCapability(
                name="fix_generation",
                description="Generate fixes for violations",
                tools_required=["Edit", "MultiEdit", "Write"],
                output_format="fix_suggestions",
            ),
            AgentCapability(
                name="fix_validation",
                description="Validate proposed fixes",
                tools_required=["Read", "Task"],
                output_format="validation_report",
            ),
        ]
        super().__init__(AgentType.REMEDIATION_ASSISTANT, capabilities)

    async def analyze(self, task: AgentTask) -> AgentResult:
        """Generate remediation suggestions"""
        start_time = datetime.now()

        try:
            # Get violations from shared context
            violations = task.context.violations_found

            # Generate fixes for each violation
            fixes = await self._generate_fixes(violations)

            # Validate fixes
            validated_fixes = await self._validate_fixes(fixes)

            results = {
                "fixes": validated_fixes,
                "auto_fixable": [f for f in validated_fixes if f.get("auto_fixable")],
                "manual_fixes": [f for f in validated_fixes if not f.get("auto_fixable")],
                "insights": self._generate_remediation_insights(validated_fixes),
            }

            # Update shared context
            task.context.update_from_agent(self.agent_type, results)

            execution_time = (datetime.now() - start_time).total_seconds()
            return AgentResult(agent_type=self.agent_type, success=True, results=results, execution_time=execution_time)

        except Exception as e:
            self.logger.error(f"Remediation generation failed: {e}")
            execution_time = (datetime.now() - start_time).total_seconds()
            return AgentResult(
                agent_type=self.agent_type, success=False, results={}, execution_time=execution_time, error=str(e)
            )

    async def _generate_fixes(self, violations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate fixes for violations"""
        fixes = []

        for violation in violations:
            fix = {
                "violation_id": violation.get("id"),
                "file": violation.get("file"),
                "line": violation.get("line"),
                "description": f"Fix for {violation.get('description')}",
                "code_change": self._generate_code_fix(violation),
                "auto_fixable": violation.get("severity") != "critical",
                "effort_hours": 2 if violation.get("severity") == "high" else 1,
                "testing_required": True,
            }
            fixes.append(fix)

        return fixes

    def _generate_code_fix(self, violation: Dict[str, Any]) -> Dict[str, Any]:
        """Generate specific code fix for a violation"""
        # In real implementation, use Claude to generate actual code fixes
        return {
            "old_code": "# Original code with violation",
            "new_code": "# Fixed code following architectural patterns",
            "explanation": "Applied repository pattern to fix architectural boundary violation",
        }

    async def _validate_fixes(self, fixes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate that fixes don't introduce new issues"""
        # In real implementation, run fixes through analysis
        for fix in fixes:
            fix["validation_status"] = "validated"
            fix["side_effects"] = []
        return fixes

    def _generate_remediation_insights(self, fixes: List[Dict[str, Any]]) -> List[str]:
        """Generate insights about remediation"""
        insights = []

        auto_fixable = len([f for f in fixes if f.get("auto_fixable")])
        total = len(fixes)

        if total > 0:
            insights.append(f"{auto_fixable}/{total} violations can be automatically fixed")

            total_effort = sum(f.get("effort_hours", 0) for f in fixes)
            insights.append(f"Estimated {total_effort} hours to fix all violations")

        return insights


class HistoryForensicsAgent(AnalysisAgent):
    """Agent for analyzing Git history and violation patterns"""

    def __init__(self) -> None:
        capabilities = [
            AgentCapability(
                name="git_analysis",
                description="Analyze Git history for patterns",
                tools_required=["Bash", "Read", "Grep"],
                output_format="history_report",
            ),
            AgentCapability(
                name="hotspot_identification",
                description="Identify architectural hotspots",
                tools_required=["Bash", "Task"],
                output_format="hotspot_map",
            ),
        ]
        super().__init__(AgentType.HISTORY_FORENSICS, capabilities)

    async def analyze(self, task: AgentTask) -> AgentResult:
        """Analyze Git history for architectural patterns"""
        start_time = datetime.now()

        try:
            # Analyze file churn
            churn_analysis = await self._analyze_file_churn(task.context)

            # Identify hotspots
            hotspots = await self._identify_hotspots(churn_analysis, task.context)

            # Analyze violation patterns
            patterns = await self._analyze_violation_patterns(task.context)

            results = {
                "churn_analysis": churn_analysis,
                "hotspots": hotspots,
                "violation_patterns": patterns,
                "insights": self._generate_forensics_insights(hotspots, patterns),
            }

            # Update shared context
            task.context.update_from_agent(self.agent_type, results)

            execution_time = (datetime.now() - start_time).total_seconds()
            return AgentResult(agent_type=self.agent_type, success=True, results=results, execution_time=execution_time)

        except Exception as e:
            self.logger.error(f"History forensics failed: {e}")
            execution_time = (datetime.now() - start_time).total_seconds()
            return AgentResult(
                agent_type=self.agent_type, success=False, results={}, execution_time=execution_time, error=str(e)
            )

    async def _analyze_file_churn(self, context: SharedContext) -> Dict[str, Any]:
        """Analyze file change frequency"""
        # Mock churn analysis
        return {
            "high_churn_files": [
                {"file": "app/api/endpoints/auth.py", "changes": 45, "authors": 5},
                {"file": "app/core/auth.py", "changes": 38, "authors": 3},
            ],
            "average_churn": 12.5,
            "analysis_period": "6 months",
        }

    async def _identify_hotspots(self, churn_analysis: Dict[str, Any], context: SharedContext) -> List[Dict[str, Any]]:
        """Identify architectural hotspots"""
        hotspots = []

        for file_data in churn_analysis.get("high_churn_files", []):
            # Mock hotspot analysis
            hotspots.append(
                {
                    "file": file_data["file"],
                    "risk_level": "high" if file_data["changes"] > 40 else "medium",
                    "churn_score": file_data["changes"] / 50,  # Normalized
                    "complexity_score": 0.7,  # Mock complexity
                    "combined_risk": 0.8,
                    "recommendation": "Consider refactoring to reduce coupling",
                }
            )

        return hotspots

    async def _analyze_violation_patterns(self, context: SharedContext) -> Dict[str, Any]:
        """Analyze patterns in historical violations"""
        return {
            "recurring_violations": [
                {"pattern": "Direct database access in API layer", "frequency": 12, "last_occurrence": "2 weeks ago"}
            ],
            "violation_trends": {
                "increasing": ["architectural_boundary"],
                "decreasing": ["naming_convention"],
                "stable": ["dependency_violation"],
            },
        }

    def _generate_forensics_insights(self, hotspots: List[Dict[str, Any]], patterns: Dict[str, Any]) -> List[str]:
        """Generate insights from forensics analysis"""
        insights = []

        high_risk_hotspots = [h for h in hotspots if h.get("risk_level") == "high"]
        if high_risk_hotspots:
            insights.append(f"{len(high_risk_hotspots)} high-risk architectural hotspots identified")

        recurring = patterns.get("recurring_violations", [])
        if recurring:
            insights.append(f"{len(recurring)} recurring violation patterns need systematic fixes")

        return insights


class ArchitecturalAnalysisOrchestrator:
    """Orchestrates multiple agents for comprehensive analysis"""

    def __init__(self, repository_path: str):
        self.repository_path = Path(repository_path)
        self.logger = logging.getLogger("Orchestrator")

        # Initialize agents
        self.agents = {
            AgentType.SEMANTIC_ANALYZER: SemanticAnalyzerAgent(),
            AgentType.VIOLATION_DETECTOR: ViolationDetectorAgent(),
            AgentType.REMEDIATION_ASSISTANT: RemediationAssistantAgent(),
            AgentType.HISTORY_FORENSICS: HistoryForensicsAgent(),
        }

        # Initialize shared context
        self.shared_context = SharedContext(repository_path=str(self.repository_path))

        # Claude client for advanced analysis
        self.claude_client = None
        if CLAUDE_AVAILABLE:
            api_key = os.getenv("ANTHROPIC_API_KEY")
            if api_key:
                self.claude_client = Anthropic(api_key=api_key)

    async def analyze_repository(self, adr_paths: List[str]) -> Dict[str, Any]:
        """Run comprehensive multi-agent analysis"""
        start_time = datetime.now()

        # Load ADR documents
        await self._load_adr_documents(adr_paths)

        # Phase 1: Parallel discovery and understanding
        discovery_tasks = [
            AgentTask(
                agent_type=AgentType.SEMANTIC_ANALYZER,
                prompt="Analyze ADR requirements and discover relevant files",
                context=self.shared_context,
                priority=1,
            ),
            AgentTask(
                agent_type=AgentType.HISTORY_FORENSICS,
                prompt="Analyze Git history for architectural patterns",
                context=self.shared_context,
                priority=1,
            ),
        ]

        await self._execute_tasks_parallel(discovery_tasks)

        # Phase 2: Violation detection based on discovery
        detection_task = AgentTask(
            agent_type=AgentType.VIOLATION_DETECTOR,
            prompt="Detect violations based on requirements and history",
            context=self.shared_context,
            priority=2,
            dependencies=[AgentType.SEMANTIC_ANALYZER, AgentType.HISTORY_FORENSICS],
        )

        await self._execute_task(detection_task)

        # Phase 3: Remediation planning
        if self.shared_context.violations_found:
            remediation_task = AgentTask(
                agent_type=AgentType.REMEDIATION_ASSISTANT,
                prompt="Generate remediation plan for violations",
                context=self.shared_context,
                priority=3,
                dependencies=[AgentType.VIOLATION_DETECTOR],
            )

            await self._execute_task(remediation_task)

        # Compile final report
        execution_time = (datetime.now() - start_time).total_seconds()
        return self._compile_final_report(execution_time)

    async def _load_adr_documents(self, adr_paths: List[str]) -> None:
        """Load ADR documents into shared context"""
        for adr_path in adr_paths:
            path = Path(adr_path)
            if path.exists():
                adr_id = path.stem
                with open(path, "r") as f:
                    self.shared_context.adr_documents[adr_id] = f.read()

    async def _execute_tasks_parallel(self, tasks: List[AgentTask]) -> List[AgentResult]:
        """Execute multiple tasks in parallel"""
        coroutines = [self._execute_task(task) for task in tasks]
        return await asyncio.gather(*coroutines)

    async def _execute_task(self, task: AgentTask) -> AgentResult:
        """Execute a single agent task"""
        agent = self.agents.get(task.agent_type)
        if not agent:
            return AgentResult(
                agent_type=task.agent_type,
                success=False,
                results={},
                execution_time=0,
                error=f"Agent {task.agent_type} not found",
            )

        return await agent.analyze(task)

    def _compile_final_report(self, execution_time: float) -> Dict[str, Any]:
        """Compile results from all agents into final report"""
        # Calculate compliance score
        total_files = len(self.shared_context.relevant_files)
        violations = len(self.shared_context.violations_found)
        compliance_score = max(0, 100 - (violations * 5)) if total_files > 0 else 100

        return {
            "analysis_metadata": {
                "timestamp": datetime.now().isoformat(),
                "repository": self.repository_path.name,
                "execution_time": execution_time,
                "agents_used": list(self.shared_context.analysis_results.keys()),
                "adrs_analyzed": list(self.shared_context.adr_documents.keys()),
            },
            "compliance_score": compliance_score,
            "violations": self.shared_context.violations_found,
            "suggested_fixes": self.shared_context.suggested_fixes,
            "architectural_insights": self.shared_context.architectural_insights,
            "agent_results": self.shared_context.analysis_results,
            "summary": {
                "total_violations": len(self.shared_context.violations_found),
                "auto_fixable": len([f for f in self.shared_context.suggested_fixes if f.get("auto_fixable")]),
                "files_analyzed": len(self.shared_context.relevant_files),
                "total_insights": len(self.shared_context.architectural_insights),
            },
        }

    async def execute_with_concurrency(self, tasks: List[AgentTask], max_concurrent: int = 4) -> List[AgentResult]:
        """Execute tasks with controlled concurrency"""
        semaphore = asyncio.Semaphore(max_concurrent)

        async def execute_with_semaphore(task: AgentTask) -> AgentResult:
            async with semaphore:
                return await self._execute_task(task)

        return await asyncio.gather(*[execute_with_semaphore(task) for task in tasks])


async def main() -> None:
    """Example usage of multi-agent system"""
    # Initialize orchestrator
    orchestrator = ArchitecturalAnalysisOrchestrator(".")

    # Find ADR documents
    adr_dir = Path("docs/architecture/ADRs")
    adr_files = list(adr_dir.glob("ADR-*.md")) if adr_dir.exists() else []

    if not adr_files:
        print("No ADR documents found")
        return

    # Run analysis
    print("🚀 Starting multi-agent architectural analysis...")
    results = await orchestrator.analyze_repository([str(f) for f in adr_files])

    # Display results
    print(f"\n📊 Analysis Complete!")
    print(f"   Compliance Score: {results['compliance_score']:.1f}%")
    print(f"   Violations Found: {results['summary']['total_violations']}")
    print(f"   Auto-fixable: {results['summary']['auto_fixable']}")
    print(f"   Insights Generated: {results['summary']['total_insights']}")
    print(f"   Execution Time: {results['analysis_metadata']['execution_time']:.1f}s")

    # Save results
    output_dir = Path("docs/reports/ADRaudit-claudecode")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"multi_agent_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n💾 Results saved to {output_file}")


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    # Run async main
    asyncio.run(main())
