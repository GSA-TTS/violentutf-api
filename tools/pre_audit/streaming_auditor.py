#!/usr/bin/env python3
"""
Claude Code Streaming Architectural Auditor.

Real-time streaming architectural analysis for large codebases with progressive
results and continuous compliance monitoring.

Based on the Claude Code Enhanced Auditor Improvement Plan.

Author: ViolentUTF API Audit Team
License: MIT
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional

from claude_code_auditor import EnterpriseClaudeCodeConfig
from dotenv import load_dotenv

try:
    from claude_code_sdk import ClaudeCodeOptions, query
except ImportError:
    print("ERROR: Claude Code SDK is required for streaming architectural analysis.")
    print("Install with: pip install claude-code-sdk")
    print("Or install Claude Code CLI: npm install -g @anthropic/claude-code")
    raise ImportError("Claude Code SDK is required but not available")

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()


class StreamingArchitecturalAuditor:
    """Real-time streaming architectural analysis with Claude Code."""

    def __init__(self, repo_path: str):
        self.config = EnterpriseClaudeCodeConfig()
        self.repo_path = Path(repo_path)
        self.analysis_queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue()
        self.results_stream: asyncio.Queue[Dict[str, Any]] = asyncio.Queue()

        # Streaming configuration
        self.chunk_size = 50  # Files to analyze per chunk
        self.update_interval = 5  # Seconds between progress updates

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

    def _create_streaming_system_prompt(self) -> str:
        """Create system prompt optimized for streaming analysis."""
        return """You are performing real-time architectural analysis with streaming updates.

Streaming Analysis Approach:
- Provide immediate feedback as you discover violations
- Stream progress updates with specific component being analyzed
- Give incremental compliance scoring
- Report violations as they're found, not at the end

Output Format for Each Update:
{
    "analysis_type": "adr_discovery|file_analysis|violation_detected|progress_update",
    "progress_percentage": 0-100,
    "current_component": "file or ADR being analyzed",
    "findings": {
        "violations": [...],
        "compliance_score": 0-100,
        "recommendations": [...]
    },
    "timestamp": "ISO timestamp"
}

Focus Areas:
1. ADR compliance validation with streaming results
2. Progressive hotspot identification
3. Real-time violation detection
4. Continuous compliance score updates
5. Incremental recommendation generation

Available tools: Read, Grep, Glob, Bash for comprehensive analysis.
Stream results as JSON objects for real-time consumption."""

    def _create_streaming_options(self) -> ClaudeCodeOptions:
        """Create Claude Code options optimized for streaming."""
        return ClaudeCodeOptions(
            system_prompt=self._create_streaming_system_prompt(),
            max_turns=100,  # Long-running analysis
            cwd=self.repo_path,
            allowed_tools=["Read", "Grep", "Glob", "Bash"],
            permission_mode="default",
        )

    async def start_streaming_analysis(self) -> AsyncGenerator[Dict[str, Any], None]:
        """Start streaming architectural analysis."""
        logger.info("Starting streaming architectural analysis")

        options = self._create_streaming_options()

        analysis_prompt = """
        Start comprehensive streaming architectural analysis:

        PHASE 1: ADR Discovery (Stream updates as you find each ADR)
        1. Use Glob to find all ADR files
        2. Stream update for each ADR discovered
        3. Extract requirements and map to code areas

        PHASE 2: Progressive File Analysis (Stream updates for file groups)
        1. Use Glob to identify all source files
        2. Group files into logical chunks
        3. Stream analysis updates for each chunk
        4. Report violations immediately when found

        PHASE 3: Continuous Compliance Scoring
        1. Update compliance score after each file group
        2. Stream progressive recommendations
        3. Provide overall health metrics updates

        For each update, provide JSON format:
        {
            "analysis_type": "discovery|analysis|violation|summary",
            "progress_percentage": 25,
            "current_component": "docs/architecture/ADRs/ADR-002.md",
            "findings": {
                "new_violations": [...],
                "compliance_score": 78.5,
                "component_health": "good|warning|critical"
            },
            "metadata": {
                "files_processed": 15,
                "total_files": 60,
                "elapsed_time": 30.5
            }
        }

        Stream results continuously - don't wait until completion.
        """

        # Start analysis in background task
        analysis_task = asyncio.create_task(self._run_streaming_analysis(analysis_prompt, options))

        # Yield results as they become available
        start_time = time.time()

        while not analysis_task.done() or not self.results_stream.empty():
            try:
                result = await asyncio.wait_for(self.results_stream.get(), timeout=1.0)

                # Enhance result with timing information
                result["elapsed_time"] = time.time() - start_time
                result["stream_timestamp"] = datetime.now(timezone.utc).isoformat()

                yield result

                # Check for completion signal
                if result.get("type") == "analysis_complete":
                    break

            except asyncio.TimeoutError:
                # Check if analysis is still running
                if analysis_task.done():
                    break
                continue

        # Ensure task is completed
        await analysis_task
        logger.info(f"Streaming analysis completed in {time.time() - start_time:.2f} seconds")

    async def _run_streaming_analysis(self, prompt: str, options: ClaudeCodeOptions) -> None:
        """Run the streaming analysis and populate results queue."""
        try:
            async for message in query(prompt=prompt, options=options):
                processed_message = await self._process_streaming_message(message)
                if processed_message:
                    await self.results_stream.put(processed_message)

        except Exception as e:
            logger.error(f"Streaming analysis error: {e}")
            await self.results_stream.put(
                {"type": "analysis_error", "error": str(e), "timestamp": datetime.now(timezone.utc).isoformat()}
            )

        finally:
            # Signal completion
            await self.results_stream.put({"type": "analysis_complete"})

    async def _process_streaming_message(self, message: Any) -> Optional[Dict[str, Any]]:
        """Process a streaming message from Claude Code."""
        try:
            content = self._extract_message_content(message)
            if not content:
                return None

            if hasattr(message, "type") and message.type == "analysis_update":
                # Try to parse JSON content
                if content.startswith("{") and content.endswith("}"):
                    try:
                        parsed_content = json.loads(content)
                        return {
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "message_type": "structured_update",
                            "content": parsed_content,
                            "metadata": getattr(message, "metadata", {}),
                        }
                    except json.JSONDecodeError:
                        pass

                # Handle text-based streaming updates
                return {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "message_type": "text_update",
                    "content": content,
                    "metadata": getattr(message, "metadata", {}),
                }

            else:
                # Handle general content messages
                return {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "message_type": "general",
                    "content": content,
                    "metadata": getattr(message, "metadata", {}),
                }

        except Exception as e:
            logger.warning(f"Error processing streaming message: {e}")
            return None

    async def analyze_with_progress_callback(self, progress_callback: Optional[Any] = None) -> Dict[str, Any]:
        """Run streaming analysis with progress callback."""
        results: Dict[str, Any] = {
            "analysis_metadata": {
                "start_time": datetime.now(timezone.utc).isoformat(),
                "repo_path": str(self.repo_path),
            },
            "progress_updates": [],
            "violations": [],
            "compliance_scores": [],
            "final_results": {},
        }

        violation_count = 0
        latest_score = 0.0

        async for update in self.start_streaming_analysis():
            results["progress_updates"].append(update)

            # Extract violations from update
            if update.get("message_type") == "structured_update":
                content = update.get("content", {})
                findings = content.get("findings", {})

                new_violations = findings.get("new_violations", [])
                if new_violations:
                    results["violations"].extend(new_violations)
                    violation_count += len(new_violations)

                compliance_score = findings.get("compliance_score")
                if compliance_score is not None:
                    latest_score = compliance_score
                    results["compliance_scores"].append(
                        {
                            "score": compliance_score,
                            "timestamp": update.get("timestamp"),
                            "component": content.get("current_component"),
                        }
                    )

                # Call progress callback if provided
                if progress_callback:
                    await progress_callback(
                        {
                            "progress": content.get("progress_percentage", 0),
                            "component": content.get("current_component", "unknown"),
                            "violations_found": violation_count,
                            "current_score": latest_score,
                            "elapsed_time": update.get("elapsed_time", 0),
                        }
                    )

        # Finalize results
        results["final_results"] = {
            "total_violations": len(results["violations"]),
            "final_compliance_score": latest_score,
            "analysis_duration": time.time()
            - time.mktime(
                datetime.fromisoformat(results["analysis_metadata"]["start_time"].replace("Z", "+00:00")).timetuple()
            ),
            "completion_timestamp": datetime.now(timezone.utc).isoformat(),
        }

        return results


class ProgressTracker:
    """Helper class for tracking and displaying streaming analysis progress."""

    def __init__(self, display_interval: float = 2.0):
        self.display_interval = display_interval
        self.last_display = 0.0
        self.start_time = time.time()

    async def update_progress(self, progress_data: Dict[str, Any]) -> None:
        """Update and optionally display progress."""
        current_time = time.time()

        if current_time - self.last_display >= self.display_interval:
            self._display_progress(progress_data)
            self.last_display = current_time

    def _display_progress(self, data: Dict[str, Any]) -> None:
        """Display progress information."""
        progress = data.get("progress", 0)
        component = data.get("component", "unknown")
        violations = data.get("violations_found", 0)
        score = data.get("current_score", 0)
        elapsed = data.get("elapsed_time", 0)

        # Create progress bar
        bar_width = 30
        filled = int(bar_width * progress / 100)
        bar = "█" * filled + "▒" * (bar_width - filled)

        print(
            f"\r🏗️  [{bar}] {progress:5.1f}% | "
            f"Component: {component[-30:]:30} | "
            f"Violations: {violations:3d} | "
            f"Score: {score:5.1f}% | "
            f"Time: {elapsed:5.1f}s",
            end="",
            flush=True,
        )


# CLI Interface for Streaming Analysis
async def main() -> None:
    """Main CLI interface for streaming auditor."""
    import argparse

    parser = argparse.ArgumentParser(description="Claude Code Streaming Architectural Auditor")
    parser.add_argument("--repo-path", default=".", help="Path to repository root")
    parser.add_argument("--output-file", help="Save streaming results to JSON file")
    parser.add_argument("--show-progress", action="store_true", help="Show progress bar")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        auditor = StreamingArchitecturalAuditor(args.repo_path)

        progress_tracker = ProgressTracker() if args.show_progress else None

        # Run streaming analysis with progress callback
        if progress_tracker:
            results = await auditor.analyze_with_progress_callback(progress_callback=progress_tracker.update_progress)
        else:
            # Simple streaming without progress tracking
            results = {"updates": []}
            async for update in auditor.start_streaming_analysis():
                results["updates"].append(update)
                print(
                    f"Update: {update.get('message_type', 'unknown')} - "
                    f"{update.get('content', {}).get('current_component', 'N/A')}"
                )

        if args.show_progress:
            print()  # New line after progress bar

        # Display final results
        if "final_results" in results:
            final = results["final_results"]
            print(f"\n🎯 Analysis Complete:")
            print(f"   Total Violations: {final['total_violations']}")
            print(f"   Final Compliance Score: {final['final_compliance_score']:.1f}%")
            print(f"   Analysis Duration: {final['analysis_duration']:.2f}s")

        # Save results if requested
        if args.output_file:
            with open(args.output_file, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            print(f"   Results saved to: {args.output_file}")

    except Exception as e:
        logger.error(f"Streaming analysis failed: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())
