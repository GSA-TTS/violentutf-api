#!/usr/bin/env python3
"""
Incremental Architectural Analyzer

This analyzer provides incremental analysis capabilities by:
1. Tracking file changes using Git
2. Caching analysis results
3. Analyzing only changed files
4. Reusing cached results for unchanged files
"""

import asyncio
import hashlib
import json
import logging
import os
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multi_agent_auditor import ArchitecturalAnalysisOrchestrator
from pattern_analyzer import PatternAnalyzer
from safe_cache_manager import MultiTierCacheManager
from smart_analyzer import SmartArchitecturalAnalyzer


@dataclass
class FileChange:
    """Represents a file change"""

    path: str
    change_type: str  # added, modified, deleted
    old_hash: Optional[str] = None
    new_hash: Optional[str] = None
    lines_added: int = 0
    lines_deleted: int = 0

    @property
    def is_significant(self) -> bool:
        """Check if change is significant enough to re-analyze"""
        # Deleted files don't need analysis
        if self.change_type == "deleted":
            return False
        # New files always need analysis
        if self.change_type == "added":
            return True
        # Modified files with substantial changes
        return (self.lines_added + self.lines_deleted) > 10


@dataclass
class DependencyGraph:
    """Tracks file dependencies for impact analysis"""

    dependencies: Dict[str, Set[str]] = field(default_factory=dict)
    dependents: Dict[str, Set[str]] = field(default_factory=dict)

    def add_dependency(self, file: str, depends_on: str) -> None:
        """Add a dependency relationship"""
        if file not in self.dependencies:
            self.dependencies[file] = set()
        self.dependencies[file].add(depends_on)

        if depends_on not in self.dependents:
            self.dependents[depends_on] = set()
        self.dependents[depends_on].add(file)

    def get_affected_files(self, changed_files: List[str]) -> Set[str]:
        """Get all files affected by changes"""
        affected = set(changed_files)

        # Add all dependents recursively
        to_process = list(changed_files)
        processed = set()

        while to_process:
            file = to_process.pop()
            if file in processed:
                continue
            processed.add(file)

            # Add direct dependents
            if file in self.dependents:
                for dependent in self.dependents[file]:
                    affected.add(dependent)
                    to_process.append(dependent)

        return affected


class FileChangeTracker:
    """Tracks file changes using Git"""

    def __init__(self, repo_path: str = "."):
        self.repo_path = Path(repo_path)
        self.logger = logging.getLogger("FileChangeTracker")

    def get_changed_files(self, base_ref: str = "HEAD~1") -> List[FileChange]:
        """Get list of changed files since base reference"""
        changes = []

        try:
            # Get list of changed files with status
            result = subprocess.run(
                ["git", "diff", "--name-status", "--no-renames", base_ref],
                capture_output=True,
                text=True,
                check=True,
                cwd=str(self.repo_path),  # Ensure string path
            )

            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue

                parts = line.split("\t")
                if len(parts) >= 2:
                    status = parts[0]
                    file_path = parts[1]

                    # Only track Python files
                    if not file_path.endswith(".py"):
                        continue

                    change_type = self._map_git_status(status)
                    if change_type:
                        # Get detailed change info
                        change = self._get_file_change_details(file_path, base_ref, change_type)
                        changes.append(change)

            return changes

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to get changed files: {e}")
            return []

    def _map_git_status(self, status: str) -> Optional[str]:
        """Map Git status to change type"""
        mapping = {
            "A": "added",
            "M": "modified",
            "D": "deleted",
            "C": "copied",
            "R": "renamed",
            "T": "modified",  # Type change
            "U": "modified",  # Unmerged
            "X": "unknown",
            "B": "broken",
        }
        return mapping.get(status[0])

    def _get_file_change_details(self, file_path: str, base_ref: str, change_type: str) -> FileChange:
        """Get detailed information about file change"""
        change = FileChange(path=file_path, change_type=change_type)

        try:
            # Get line changes
            if change_type != "added":
                result = subprocess.run(
                    ["git", "diff", "--numstat", base_ref, "--", file_path],
                    capture_output=True,
                    text=True,
                    check=True,
                    cwd=self.repo_path,
                )

                if result.stdout:
                    parts = result.stdout.strip().split("\t")
                    if len(parts) >= 3:
                        change.lines_added = int(parts[0]) if parts[0] != "-" else 0
                        change.lines_deleted = int(parts[1]) if parts[1] != "-" else 0

            # Get file hashes
            if change_type != "deleted":
                change.new_hash = self._get_file_hash(file_path)

            if change_type == "modified":
                # Get old hash
                result = subprocess.run(
                    ["git", "show", f"{base_ref}:{file_path}"],
                    capture_output=True,
                    text=True,
                    check=True,
                    cwd=self.repo_path,
                )
                if result.stdout:
                    change.old_hash = hashlib.sha256(result.stdout.encode()).hexdigest()[:16]

        except subprocess.CalledProcessError:
            pass

        return change

    def _get_file_hash(self, file_path: str) -> str:
        """Get hash of current file content"""
        full_path = self.repo_path / file_path
        if full_path.exists():
            with open(full_path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()[:16]
        return ""

    def build_dependency_graph(self, python_files: List[str]) -> DependencyGraph:
        """Build dependency graph from imports"""
        graph = DependencyGraph()

        for file_path in python_files:
            dependencies = self._extract_dependencies(file_path)
            for dep in dependencies:
                graph.add_dependency(file_path, dep)

        return graph

    def _extract_dependencies(self, file_path: str) -> Set[str]:
        """Extract dependencies from Python file imports"""
        dependencies: Set[str] = set()
        full_path = self.repo_path / file_path

        if not full_path.exists():
            return dependencies

        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Extract imports (simplified)
            import_lines = []
            for line in content.split("\n"):
                line = line.strip()
                if line.startswith("import ") or line.startswith("from "):
                    import_lines.append(line)

            # Parse imports to find local dependencies
            for line in import_lines:
                if line.startswith("from app"):
                    # Local import
                    parts = line.split()
                    if len(parts) >= 2:
                        module_path = parts[1].replace(".", "/") + ".py"
                        if (self.repo_path / module_path).exists():
                            dependencies.add(module_path)
                elif line.startswith("import app"):
                    # Direct import
                    parts = line.split()
                    if len(parts) >= 2:
                        module_path = parts[1].replace(".", "/") + ".py"
                        if (self.repo_path / module_path).exists():
                            dependencies.add(module_path)

        except Exception as e:
            self.logger.warning(f"Failed to extract dependencies from {file_path}: {e}")

        return dependencies


class IncrementalAnalyzer:
    """Performs incremental architectural analysis"""

    def __init__(self, repo_path: str = ".", config: Optional[Dict[str, Any]] = None):
        self.repo_path = Path(repo_path)
        self.config = config or {}
        self.logger = logging.getLogger("IncrementalAnalyzer")

        # Initialize components
        self.cache_manager = MultiTierCacheManager(self.config.get("cache", {}))
        self.change_tracker = FileChangeTracker(str(self.repo_path))
        self.smart_analyzer = SmartArchitecturalAnalyzer()
        self.pattern_analyzer = PatternAnalyzer()

        # Multi-agent orchestrator (if Claude available)
        self.orchestrator: Optional[ArchitecturalAnalysisOrchestrator]
        try:
            self.orchestrator = ArchitecturalAnalysisOrchestrator(str(self.repo_path))
        except:
            self.orchestrator = None
            self.logger.warning("Multi-agent orchestrator not available")

    async def analyze_changes(
        self, base_ref: str = "HEAD~1", use_claude: bool = True, force_reanalysis: bool = False
    ) -> Dict[str, Any]:
        """Analyze only changed files incrementally"""
        start_time = datetime.now()

        # Get changed files
        changes = self.change_tracker.get_changed_files(base_ref)

        if not changes:
            return {
                "analysis_type": "incremental",
                "timestamp": datetime.now().isoformat(),
                "base_ref": base_ref,
                "changes_detected": False,
                "files_analyzed": 0,
                "cached_results_used": 0,
                "compliance_score": 100.0,
                "violations": [],
            }

        # Build dependency graph for impact analysis
        all_py_files = self._get_all_python_files()
        dependency_graph = self.change_tracker.build_dependency_graph(all_py_files)

        # Determine files to analyze
        changed_files = [c.path for c in changes if c.is_significant]
        affected_files = dependency_graph.get_affected_files(changed_files)

        self.logger.info(f"Changed files: {len(changed_files)}, Affected files: {len(affected_files)}")

        # Separate cached and uncached files
        cached_results = {}
        files_to_analyze = []

        if not force_reanalysis:
            for file_path in affected_files:
                cache_key = await self._get_cache_key(file_path)
                cached_result = await self.cache_manager.get(cache_key)

                if cached_result:
                    cached_results[file_path] = cached_result
                else:
                    files_to_analyze.append(file_path)
        else:
            files_to_analyze = list(affected_files)

        self.logger.info(f"Using {len(cached_results)} cached results, analyzing {len(files_to_analyze)} files")

        # Analyze uncached files
        new_results = {}
        if files_to_analyze:
            if use_claude and self.orchestrator:
                # Use multi-agent analysis
                new_results = await self._analyze_with_claude(files_to_analyze)
            else:
                # Use pattern-based analysis
                new_results = await self._analyze_with_patterns(files_to_analyze)

            # Cache new results
            for file_path, result in new_results.items():
                cache_key = await self._get_cache_key(file_path)
                await self.cache_manager.set(cache_key, result)

        # Combine results
        all_results = {**cached_results, **new_results}

        # Generate summary
        execution_time = (datetime.now() - start_time).total_seconds()
        summary = self._generate_summary(
            all_results, changes, len(cached_results), len(files_to_analyze), execution_time, base_ref
        )

        return summary

    async def _get_cache_key(self, file_path: str) -> str:
        """Generate cache key for a file"""
        file_hash = self.change_tracker._get_file_hash(file_path)
        return self.cache_manager.generate_key("architectural_analysis", file_path, file_hash)

    async def _analyze_with_claude(self, files: List[str]) -> Dict[str, Any]:
        """Analyze files using Claude multi-agent system"""
        # For simplicity, analyze all files together
        adr_paths = self._find_adr_files()

        if self.orchestrator is None:
            return {}

        results = await self.orchestrator.analyze_repository(adr_paths)

        # Map results to individual files
        file_results = {}
        for file_path in files:
            file_violations = [v for v in results.get("violations", []) if v.get("file") == file_path]

            file_results[file_path] = {
                "violations": file_violations,
                "analysis_type": "claude_multi_agent",
                "timestamp": datetime.now().isoformat(),
            }

        return file_results

    async def _analyze_with_patterns(self, files: List[str]) -> Dict[str, Any]:
        """Analyze files using pattern matching"""
        file_results = {}

        for file_path in files:
            violations = self.pattern_analyzer.analyze_file(file_path)

            file_results[file_path] = {
                "violations": [self._violation_to_dict(v) for v in violations],
                "analysis_type": "pattern_based",
                "timestamp": datetime.now().isoformat(),
            }

        return file_results

    def _violation_to_dict(self, violation: Any) -> Dict[str, Any]:
        """Convert violation object to dictionary"""
        return {
            "file": violation.file_path,
            "line": violation.line_number,
            "severity": violation.severity,
            "description": violation.description,
            "adr_id": violation.adr_id,
            "pattern_id": violation.pattern_id,
            "confidence": violation.confidence,
        }

    def _generate_summary(
        self,
        results: Dict[str, Any],
        changes: List[FileChange],
        cached_count: int,
        analyzed_count: int,
        execution_time: float,
        base_ref: str,
    ) -> Dict[str, Any]:
        """Generate analysis summary"""
        # Collect all violations
        all_violations = []
        for file_results in results.values():
            all_violations.extend(file_results.get("violations", []))

        # Calculate compliance score
        total_files = len(results)
        files_with_violations = len(set(v.get("file") for v in all_violations))
        compliance_score = max(0, 100 * (1 - files_with_violations / max(total_files, 1)))

        # Group violations
        violations_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in all_violations:
            severity = v.get("severity", "medium")
            violations_by_severity[severity] = violations_by_severity.get(severity, 0) + 1

        return {
            "analysis_type": "incremental",
            "timestamp": datetime.now().isoformat(),
            "base_ref": base_ref,
            "execution_time": execution_time,
            "changes_summary": {
                "total_changes": len(changes),
                "files_added": len([c for c in changes if c.change_type == "added"]),
                "files_modified": len([c for c in changes if c.change_type == "modified"]),
                "files_deleted": len([c for c in changes if c.change_type == "deleted"]),
            },
            "analysis_summary": {
                "files_analyzed": analyzed_count,
                "cached_results_used": cached_count,
                "total_files_checked": len(results),
            },
            "compliance_score": compliance_score,
            "total_violations": len(all_violations),
            "violations_by_severity": violations_by_severity,
            "violations": all_violations,
            "cache_stats": self._get_cache_stats(),
        }

    def _get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        # TODO: Implement cache statistics when available
        return {
            "memory": {
                "hit_rate": 0.0,
                "hits": 0,
                "misses": 0,
                "entries": 0,
            }
        }

    def _get_all_python_files(self) -> List[str]:
        """Get all Python files in repository"""
        py_files = []

        for root, _, files in os.walk(self.repo_path):
            # Skip virtual environments and caches
            if any(skip in root for skip in ["venv", "__pycache__", ".git", "node_modules"]):
                continue

            for file in files:
                if file.endswith(".py"):
                    rel_path = os.path.relpath(os.path.join(root, file), self.repo_path)
                    py_files.append(rel_path)

        return py_files

    def _find_adr_files(self) -> List[str]:
        """Find ADR documentation files"""
        adr_files = []
        adr_dir = self.repo_path / "docs" / "architecture" / "ADRs"

        if adr_dir.exists():
            for file in adr_dir.glob("ADR-*.md"):
                adr_files.append(str(file))

        return adr_files


async def main() -> None:
    """Example usage"""
    import argparse

    parser = argparse.ArgumentParser(description="Incremental Architectural Analyzer")
    parser.add_argument("--base-ref", default="HEAD~1", help="Base reference for comparison")
    parser.add_argument("--use-claude", action="store_true", help="Use Claude for analysis")
    parser.add_argument("--force", action="store_true", help="Force re-analysis (ignore cache)")
    parser.add_argument("--output", help="Output file for results")

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    # Initialize analyzer
    analyzer = IncrementalAnalyzer()

    # Run analysis
    print("🔄 Running incremental architectural analysis...")
    results = await analyzer.analyze_changes(
        base_ref=args.base_ref, use_claude=args.use_claude, force_reanalysis=args.force
    )

    # Display results
    print(f"\n📊 Analysis Complete!")
    print(f"   Base Reference: {results['base_ref']}")
    print(f"   Files Analyzed: {results['analysis_summary']['files_analyzed']}")
    print(f"   Cached Results: {results['analysis_summary']['cached_results_used']}")
    print(f"   Compliance Score: {results['compliance_score']:.1f}%")
    print(f"   Total Violations: {results['total_violations']}")
    print(f"   Execution Time: {results['execution_time']:.1f}s")

    # Cache statistics
    print("\n📦 Cache Performance:")
    for tier, stats in results["cache_stats"].items():
        print(f"   {tier}: Hit Rate={stats['hit_rate']:.1%} (Hits={stats['hits']}, Misses={stats['misses']})")

    # Save results if requested
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n💾 Results saved to {args.output}")


if __name__ == "__main__":
    asyncio.run(main())
