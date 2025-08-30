#!/usr/bin/env python3
"""
Claude Code Intelligent Remediation Planner.

AI-powered remediation planning with implementation guidance for architectural
violations. Generates step-by-step fixes with code examples and risk assessment.

Based on the Claude Code Enhanced Auditor Improvement Plan.

Author: ViolentUTF API Audit Team
License: MIT
"""

import asyncio
import json
import logging
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from claude_code_auditor import EnterpriseClaudeCodeConfig
from dotenv import load_dotenv

try:
    from claude_code_sdk import ClaudeCodeOptions, query
except ImportError:
    print("ERROR: Claude Code SDK is required for remediation planning.")
    print("Install with: pip install claude-code-sdk")
    print("Or install Claude Code CLI: npm install -g @anthropic/claude-code")
    raise ImportError("Claude Code SDK is required but not available")

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Load environment variables from dedicated config file
env_file = Path(__file__).parent / ".env.claude_audit"
if not env_file.exists():
    env_example = Path(__file__).parent / ".env.claude_audit.example"
    if env_example.exists():
        shutil.copy(env_example, env_file)
        logger.info(f"Created {env_file} from example file")
load_dotenv(dotenv_path=env_file)


class RemediationPlan:
    """Represents a comprehensive remediation plan for architectural violations."""

    def __init__(
        self,
        plan_id: str,
        violation_group: List[Dict[str, Any]],
        priority: str,
        effort_estimate: str,
        implementation_steps: List[str],
        code_examples: str,
        testing_strategy: str,
        risk_assessment: Dict[str, Any],
        dependencies: Optional[List[str]] = None,
    ):
        self.plan_id = plan_id
        self.violation_group = violation_group
        self.priority = priority  # critical, high, medium, low
        self.effort_estimate = effort_estimate
        self.implementation_steps = implementation_steps
        self.code_examples = code_examples
        self.testing_strategy = testing_strategy
        self.risk_assessment = risk_assessment
        self.dependencies = dependencies or []
        self.created_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert remediation plan to dictionary."""
        return {
            "plan_id": self.plan_id,
            "violation_group": self.violation_group,
            "priority": self.priority,
            "effort_estimate": self.effort_estimate,
            "implementation_steps": self.implementation_steps,
            "code_examples": self.code_examples,
            "testing_strategy": self.testing_strategy,
            "risk_assessment": self.risk_assessment,
            "dependencies": self.dependencies,
            "created_at": self.created_at,
        }


class IntelligentRemediationPlanner:
    """AI-powered remediation planning with implementation guidance."""

    def __init__(self, repo_path: str):
        self.config = EnterpriseClaudeCodeConfig()
        self.repo_path = Path(repo_path)

    def _extract_message_content(self, message: Any) -> str:
        """Extract text content from a Claude Code SDK message."""
        if not hasattr(message, "content") or not message.content:
            return ""

        content = ""
        try:
            for block in message.content:
                if hasattr(block, "text"):
                    content += block.text
        except (TypeError, AttributeError):
            # Handle case where content might be a string
            if isinstance(message.content, str):
                content = message.content
            else:
                content = str(message.content)

        return content.strip()

    def _create_remediation_system_prompt(self) -> str:
        """Create system prompt for remediation planning."""
        return """You are a Senior Technical Lead and Remediation Expert specializing in:

- Prioritizing architectural violations by business impact and risk
- Creating detailed, implementable remediation plans
- Estimating effort and complexity for architectural fixes
- Sequencing changes to minimize system disruption
- Providing code examples and implementation guidance
- Designing comprehensive testing strategies

Remediation Planning Approach:
1. Analyze root causes, not just symptoms
2. Group related violations for efficient batch fixes
3. Prioritize by business impact, security risk, and technical debt
4. Create step-by-step implementation guides
5. Provide working code examples and patterns
6. Design testing strategies to validate fixes
7. Assess implementation risks and mitigation strategies

Output Format (JSON):
{
    "remediation_plan": {
        "plan_id": "REMEDIATION-001",
        "violation_group": [...],
        "priority": "critical|high|medium|low",
        "effort_estimate": "hours/days/weeks",
        "implementation_steps": [
            "Step 1: Detailed action",
            "Step 2: Next action with specifics"
        ],
        "code_examples": "Complete, working code examples",
        "testing_strategy": "Unit, integration, and validation tests",
        "risk_assessment": {
            "technical_risk": "low|medium|high",
            "business_impact": "low|medium|high",
            "rollback_plan": "How to revert if needed",
            "mitigation_strategies": [...]
        },
        "dependencies": ["Other fixes required first"]
    }
}

Focus on actionable, production-ready guidance that developers can implement immediately."""

    def _create_remediation_options(self, permission_mode: str = "default") -> ClaudeCodeOptions:
        """Create Claude Code options for remediation planning."""
        return ClaudeCodeOptions(
            system_prompt=self._create_remediation_system_prompt(),
            max_turns=20,
            cwd=self.repo_path,
            allowed_tools=["Read", "Grep", "Glob"],
            permission_mode=permission_mode,
        )

    async def create_remediation_plan(self, violations: List[Dict[str, Any]]) -> List[RemediationPlan]:
        """Create comprehensive remediation plan for architectural violations."""
        logger.info(f"Creating remediation plan for {len(violations)} violations")

        if not violations:
            return []

        # Group related violations
        violation_groups = self._group_related_violations(violations)
        remediation_plans = []

        for group_id, violation_group in enumerate(violation_groups):
            plan = await self._create_plan_for_group(group_id, violation_group)
            if plan:
                remediation_plans.append(plan)

        # Sort plans by priority and dependencies
        sorted_plans = self._sort_plans_by_priority(remediation_plans)

        logger.info(f"Generated {len(sorted_plans)} remediation plans")
        return sorted_plans

    def _group_related_violations(self, violations: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
        """Group related violations that can be fixed together."""
        groups = []
        processed = set()

        for i, violation in enumerate(violations):
            if i in processed:
                continue

            group = [violation]
            processed.add(i)

            # Find related violations
            for j, other_violation in enumerate(violations):
                if j in processed or i == j:
                    continue

                if self._are_violations_related(violation, other_violation):
                    group.append(other_violation)
                    processed.add(j)

            groups.append(group)

        return groups

    def _are_violations_related(self, v1: Dict[str, Any], v2: Dict[str, Any]) -> bool:
        """Determine if two violations are related and can be fixed together."""
        # Same ADR
        if v1.get("adr_id") == v2.get("adr_id"):
            return True

        # Same file
        if v1.get("file_path") == v2.get("file_path"):
            return True

        # Similar violation types (basic heuristic)
        desc1 = v1.get("description", "").lower()
        desc2 = v2.get("description", "").lower()

        # Common architectural issues that often go together
        related_patterns = [
            ["dependency", "injection", "coupling"],
            ["layer", "layering", "architecture"],
            ["security", "authentication", "authorization"],
            ["logging", "audit", "monitoring"],
        ]

        for patterns in related_patterns:
            if any(p in desc1 for p in patterns) and any(p in desc2 for p in patterns):
                return True

        return False

    async def _create_plan_for_group(
        self, group_id: int, violation_group: List[Dict[str, Any]]
    ) -> Optional[RemediationPlan]:
        """Create remediation plan for a group of related violations."""

        options = self._create_remediation_options()

        violations_summary = self._create_violations_summary(violation_group)

        planning_prompt = f"""
        Create a comprehensive remediation plan for these related architectural violations:

        VIOLATION GROUP {group_id + 1}:
        {violations_summary}

        Analysis Requirements:
        1. Read relevant files to understand current implementation
        2. Analyze root causes across all violations in the group
        3. Design unified solution that addresses all violations
        4. Create step-by-step implementation plan
        5. Provide working code examples
        6. Design comprehensive testing strategy
        7. Assess risks and create mitigation plan

        Planning Considerations:
        - Group violations by common root cause
        - Prioritize by business impact and technical risk
        - Sequence changes to minimize system disruption
        - Provide concrete, actionable steps
        - Include code examples that developers can use directly
        - Consider backward compatibility
        - Plan for rollback if needed

        Generate detailed remediation plan in JSON format as specified in system prompt.
        """

        try:
            async for message in query(prompt=planning_prompt, options=options):
                content = self._extract_message_content(message)
                if content:
                    try:
                        # Extract JSON from response
                        if "{" in content and "}" in content:
                            start_idx = content.find("{")
                            end_idx = content.rfind("}") + 1
                            json_str = content[start_idx:end_idx]
                            parsed_result = json.loads(json_str)

                            if "remediation_plan" in parsed_result:
                                plan_data = parsed_result["remediation_plan"]

                                return RemediationPlan(
                                    plan_id=plan_data.get("plan_id", f"REMEDIATION-{group_id + 1:03d}"),
                                    violation_group=violation_group,
                                    priority=plan_data.get("priority", "medium"),
                                    effort_estimate=plan_data.get("effort_estimate", "unknown"),
                                    implementation_steps=plan_data.get("implementation_steps", []),
                                    code_examples=plan_data.get("code_examples", ""),
                                    testing_strategy=plan_data.get("testing_strategy", ""),
                                    risk_assessment=plan_data.get("risk_assessment", {}),
                                    dependencies=plan_data.get("dependencies", []),
                                )

                    except json.JSONDecodeError:
                        logger.warning(f"Could not parse remediation plan for group {group_id}")
                        continue

        except Exception as e:
            logger.error(f"Error creating remediation plan for group {group_id}: {e}")

        return None

    def _create_violations_summary(self, violations: List[Dict[str, Any]]) -> str:
        """Create a formatted summary of violations for planning."""
        summary_parts = []

        for i, violation in enumerate(violations, 1):
            summary_parts.append(
                f"""
        Violation {i}:
        - File: {violation.get('file_path', 'unknown')}
        - Line: {violation.get('line_number', 'unknown')}
        - ADR: {violation.get('adr_id', 'unknown')}
        - Risk: {violation.get('risk_level', 'unknown')}
        - Description: {violation.get('description', 'No description')}
        - Current Fix Suggestion: {violation.get('remediation_suggestion', 'None provided')}
            """
            )

        return "\n".join(summary_parts)

    def _sort_plans_by_priority(self, plans: List[RemediationPlan]) -> List[RemediationPlan]:
        """Sort remediation plans by priority and dependencies."""
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        # Simple priority sort (dependency resolution would be more complex)
        return sorted(
            plans,
            key=lambda p: (
                priority_order.get(p.priority, 4),
                len(p.dependencies),  # Fewer dependencies first
                len(p.violation_group),  # More violations per plan = higher impact
            ),
        )

    async def generate_fix_implementation(self, violation: Dict[str, Any]) -> Dict[str, Any]:
        """Generate specific implementation code for fixing a single violation."""
        logger.info(f"Generating fix implementation for {violation.get('adr_id', 'unknown')} violation")

        implementation_options = ClaudeCodeOptions(
            system_prompt="""You are implementing architectural fixes with production-ready code.

Implementation Requirements:
1. Generate complete, working code examples
2. Provide step-by-step implementation instructions
3. Include comprehensive unit and integration tests
4. Update related documentation
5. Follow architectural best practices
6. Maintain backward compatibility where possible
7. Include error handling and edge cases

Output Format (JSON):
{
    "implementation": {
        "violation_summary": "Brief description of what's being fixed",
        "before_code": "Current problematic code",
        "after_code": "Fixed code implementation",
        "implementation_steps": [
            "Detailed step-by-step instructions"
        ],
        "test_code": "Complete test code to validate the fix",
        "documentation_updates": "Any docs that need updating",
        "deployment_notes": "Special considerations for deployment",
        "architectural_benefits": "Why this fix improves the architecture"
    }
}

Focus on production-ready, maintainable solutions.""",
            max_turns=15,
            cwd=self.repo_path,
            allowed_tools=["Read", "Write"],
            permission_mode="acceptEdits",  # Allow code generation for fixes
        )

        implementation_prompt = f"""
        Generate production-ready implementation to fix this architectural violation:

        VIOLATION DETAILS:
        - File: {violation.get('file_path', 'unknown')}
        - Line: {violation.get('line_number', 'unknown')}
        - ADR: {violation.get('adr_id', 'unknown')}
        - Risk Level: {violation.get('risk_level', 'unknown')}
        - Description: {violation.get('description', 'No description')}
        - Current Suggestion: {violation.get('remediation_suggestion', 'None')}

        Implementation Process:
        1. Read the current file to understand context
        2. Analyze the violation and root cause
        3. Design the proper architectural solution
        4. Generate corrected code with proper patterns
        5. Create comprehensive tests to validate the fix
        6. Document the architectural benefits

        Provide complete implementation in JSON format as specified.
        Make the solution production-ready and maintainable.
        """

        implementation_result = {
            "violation": violation,
            "implementation": {},
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            async for message in query(prompt=implementation_prompt, options=implementation_options):
                content = self._extract_message_content(message)
                if content:
                    try:
                        if "{" in content and "}" in content:
                            start_idx = content.find("{")
                            end_idx = content.rfind("}") + 1
                            json_str = content[start_idx:end_idx]
                            parsed_result = json.loads(json_str)

                            if "implementation" in parsed_result:
                                implementation_result["implementation"] = parsed_result["implementation"]
                                break

                    except json.JSONDecodeError:
                        logger.warning("Could not parse implementation response")
                        continue

        except Exception as e:
            logger.error(f"Error generating fix implementation: {e}")
            implementation_result["error"] = str(e)

        return implementation_result

    async def save_remediation_plans(self, plans: List[RemediationPlan], output_file: Optional[str] = None) -> str:
        """Save remediation plans to file."""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = self.config.reports_dir / f"remediation_plans_{timestamp}.json"
        else:
            output_path = Path(output_file)

        plans_data = {
            "metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "repo_path": str(self.repo_path),
                "total_plans": len(plans),
            },
            "plans": [plan.to_dict() for plan in plans],
            "execution_summary": self._generate_execution_summary(plans),
        }

        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(plans_data, f, indent=2, ensure_ascii=False)

        logger.info(f"Remediation plans saved to {output_path}")
        return str(output_path)

    def _generate_execution_summary(self, plans: List[RemediationPlan]) -> Dict[str, Any]:
        """Generate execution summary for remediation plans."""
        priority_counts: Dict[str, int] = {}
        total_violations = 0

        for plan in plans:
            priority = plan.priority
            priority_counts[priority] = priority_counts.get(priority, 0) + 1
            total_violations += len(plan.violation_group)

        return {
            "total_remediation_plans": len(plans),
            "total_violations_addressed": total_violations,
            "plans_by_priority": priority_counts,
            "estimated_total_effort": "Review individual plans for effort estimates",
            "recommended_execution_order": [plan.plan_id for plan in plans],
        }


# CLI Interface for Remediation Planning
async def main() -> None:
    """Main CLI interface for remediation planner."""
    import argparse

    parser = argparse.ArgumentParser(description="Claude Code Intelligent Remediation Planner")
    parser.add_argument("--repo-path", default=".", help="Path to repository root")
    parser.add_argument(
        "--violations-file",
        required=True,
        help="JSON file containing violations to remediate",
    )
    parser.add_argument("--output-file", help="Output file for remediation plans")
    parser.add_argument(
        "--generate-implementation",
        action="store_true",
        help="Generate implementation code for each violation",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        # Load violations
        with open(args.violations_file, "r", encoding="utf-8") as f:
            violations_data = json.load(f)

        # Extract violations from various possible formats
        violations = []
        if isinstance(violations_data, list):
            violations = violations_data
        elif "violations" in violations_data:
            violations = violations_data["violations"]
        elif "all_violations" in violations_data:
            violations = violations_data["all_violations"]
        else:
            print("Could not find violations in input file")
            return

        if not violations:
            print("No violations found to remediate")
            return

        print(f"Planning remediation for {len(violations)} violations...")

        # Create remediation planner
        planner = IntelligentRemediationPlanner(args.repo_path)

        # Generate remediation plans
        plans = await planner.create_remediation_plan(violations)

        if not plans:
            print("No remediation plans could be generated")
            return

        # Save plans
        output_file = await planner.save_remediation_plans(plans, args.output_file)

        # Display summary
        print(f"\n🔧 Remediation Planning Complete:")
        print(f"   Generated Plans: {len(plans)}")
        print(f"   Total Violations: {sum(len(p.violation_group) for p in plans)}")

        priority_counts: Dict[str, int] = {}
        for plan in plans:
            priority_counts[plan.priority] = priority_counts.get(plan.priority, 0) + 1

        print("   Plans by Priority:")
        for priority, count in sorted(priority_counts.items()):
            print(f"     {priority.title()}: {count}")

        print(f"   Saved to: {output_file}")

        # Generate implementations if requested
        if args.generate_implementation:
            print("\n🛠️  Generating implementation code...")
            implementations_dir = Path(output_file).parent / "implementations"
            implementations_dir.mkdir(exist_ok=True)

            for plan in plans[:3]:  # Limit to first 3 plans to avoid overwhelming output
                for violation in plan.violation_group:
                    impl = await planner.generate_fix_implementation(violation)

                    impl_file = (
                        implementations_dir / f"fix_{violation.get('adr_id', 'unknown')}_{int(time.time())}.json"
                    )
                    with open(impl_file, "w", encoding="utf-8") as f:
                        json.dump(impl, f, indent=2)

                    print(f"   Implementation saved: {impl_file}")

    except Exception as e:
        logger.error(f"Remediation planning failed: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())
