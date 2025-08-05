"""
Export manager for parallel report generation.

This module provides coordinated multi-format export capabilities
with parallel processing support for optimal performance.
"""

import asyncio
import logging
import os
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .base import ReportConfig, SecurityLevel
from .exporters import HTMLReportGenerator, JSONReportGenerator, PDFReportGenerator
from .security import InputValidator, ValidationError

logger = logging.getLogger(__name__)


class ExportManager:
    """
    Manages parallel export of reports in multiple formats.

    Coordinates the generation of HTML, PDF, and JSON reports
    using parallel processing for improved performance.
    """

    # Default export formats
    DEFAULT_FORMATS = ["html", "json", "pdf"]

    # Maximum workers for parallel processing
    MAX_WORKERS = 4

    def __init__(self, config: ReportConfig):
        """
        Initialize export manager.

        Args:
            config: Report configuration
        """
        self.config = config
        self.validator = InputValidator()

        # Determine export formats
        self.export_formats = config.export_formats or self.DEFAULT_FORMATS

        # Initialize generators
        self._init_generators()

        # Statistics
        self._export_stats = {
            "total_exports": 0,
            "successful_exports": 0,
            "failed_exports": 0,
            "total_time": 0,
            "format_times": {},
        }

    def _init_generators(self):
        """Initialize report generators based on configuration."""
        self.generators = {}

        if "html" in self.export_formats:
            self.generators["html"] = HTMLReportGenerator(self.config)

        if "json" in self.export_formats:
            self.generators["json"] = JSONReportGenerator(self.config)

        if "pdf" in self.export_formats:
            try:
                self.generators["pdf"] = PDFReportGenerator(self.config)
            except ImportError:
                logger.warning("PDF generator not available - ReportLab not installed")
                self.export_formats.remove("pdf")

    def export_all(self, audit_data: Dict[str, Any]) -> Dict[str, Path]:
        """
        Export reports in all configured formats.

        Args:
            audit_data: Validated audit data

        Returns:
            Dictionary mapping format to output path
        """
        start_time = time.time()
        self._export_stats["total_exports"] += 1

        try:
            # Validate data once
            validated_data = self.validator.validate_audit_data(audit_data)
        except ValidationError as e:
            logger.error(f"Data validation failed: {str(e)}")
            self._export_stats["failed_exports"] += 1
            raise

        results = {}

        if self.config.enable_parallel_export and len(self.export_formats) > 1:
            # Parallel export
            results = self._export_parallel(validated_data)
        else:
            # Sequential export
            results = self._export_sequential(validated_data)

        # Update statistics
        total_time = time.time() - start_time
        self._export_stats["total_time"] += total_time

        # Log results
        successful = [fmt for fmt, path in results.items() if path]
        failed = [fmt for fmt, path in results.items() if not path]

        if successful:
            self._export_stats["successful_exports"] += len(successful)
            logger.info(f"Successfully exported formats: {', '.join(successful)}")

        if failed:
            self._export_stats["failed_exports"] += len(failed)
            logger.warning(f"Failed to export formats: {', '.join(failed)}")

        logger.info(f"Export completed in {total_time:.2f} seconds")

        return results

    def _export_sequential(self, audit_data: Dict[str, Any]) -> Dict[str, Path]:
        """Export reports sequentially."""
        results = {}

        for format_name in self.export_formats:
            if format_name not in self.generators:
                logger.warning(f"No generator for format: {format_name}")
                results[format_name] = None
                continue

            try:
                start_time = time.time()
                generator = self.generators[format_name]

                logger.info(f"Generating {format_name.upper()} report...")
                output_path = generator.generate(audit_data)

                # Record timing
                export_time = time.time() - start_time
                self._export_stats["format_times"][format_name] = export_time

                results[format_name] = output_path
                logger.info(f"{format_name.upper()} report generated in {export_time:.2f}s")

            except Exception as e:
                logger.error(f"Failed to generate {format_name} report: {str(e)}")
                results[format_name] = None

        return results

    def _export_parallel(self, audit_data: Dict[str, Any]) -> Dict[str, Path]:
        """Export reports in parallel using thread pool."""
        results = {}

        # Determine number of workers
        num_workers = min(len(self.export_formats), self.MAX_WORKERS)

        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            # Submit all export tasks
            future_to_format = {}

            for format_name in self.export_formats:
                if format_name not in self.generators:
                    logger.warning(f"No generator for format: {format_name}")
                    results[format_name] = None
                    continue

                future = executor.submit(self._export_single_format, format_name, audit_data)
                future_to_format[future] = format_name

            # Process completed exports
            for future in as_completed(future_to_format):
                format_name = future_to_format[future]

                try:
                    output_path, export_time = future.result()
                    results[format_name] = output_path

                    if output_path:
                        self._export_stats["format_times"][format_name] = export_time
                        logger.info(f"{format_name.upper()} report generated in {export_time:.2f}s")

                except Exception as e:
                    logger.error(f"Failed to generate {format_name} report: {str(e)}")
                    results[format_name] = None

        return results

    def _export_single_format(self, format_name: str, audit_data: Dict[str, Any]) -> Tuple[Optional[Path], float]:
        """
        Export a single format.

        Args:
            format_name: Format to export
            audit_data: Validated audit data

        Returns:
            Tuple of (output_path, export_time)
        """
        start_time = time.time()

        try:
            generator = self.generators[format_name]
            output_path = generator.generate(audit_data)
            export_time = time.time() - start_time

            return output_path, export_time

        except Exception as e:
            logger.error(f"Export failed for {format_name}: {str(e)}")
            return None, time.time() - start_time

    async def export_all_async(self, audit_data: Dict[str, Any]) -> Dict[str, Path]:
        """
        Export reports asynchronously.

        Args:
            audit_data: Validated audit data

        Returns:
            Dictionary mapping format to output path
        """
        start_time = time.time()

        try:
            # Validate data once
            validated_data = self.validator.validate_audit_data(audit_data)
        except ValidationError as e:
            logger.error(f"Data validation failed: {str(e)}")
            raise

        # Create tasks for each format
        tasks = []
        for format_name in self.export_formats:
            if format_name in self.generators:
                task = asyncio.create_task(self._export_single_format_async(format_name, validated_data))
                tasks.append((format_name, task))

        # Wait for all tasks to complete
        results = {}
        for format_name, task in tasks:
            try:
                output_path = await task
                results[format_name] = output_path
            except Exception as e:
                logger.error(f"Async export failed for {format_name}: {str(e)}")
                results[format_name] = None

        total_time = time.time() - start_time
        logger.info(f"Async export completed in {total_time:.2f} seconds")

        return results

    async def _export_single_format_async(self, format_name: str, audit_data: Dict[str, Any]) -> Optional[Path]:
        """
        Export a single format asynchronously.

        Args:
            format_name: Format to export
            audit_data: Validated audit data

        Returns:
            Output path or None
        """
        loop = asyncio.get_event_loop()

        # Run generator in thread pool
        generator = self.generators[format_name]
        output_path = await loop.run_in_executor(None, generator.generate, audit_data)  # Use default executor

        return output_path

    def export_to_archive(self, audit_data: Dict[str, Any], archive_name: Optional[str] = None) -> Path:
        """
        Export all formats and create a ZIP archive.

        Args:
            audit_data: Validated audit data
            archive_name: Optional archive name

        Returns:
            Path to created archive
        """
        import zipfile

        # Generate all reports
        results = self.export_all(audit_data)

        # Create archive name
        if not archive_name:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            archive_name = f"audit_reports_{timestamp}.zip"

        archive_path = self.config.output_dir / archive_name

        # Create ZIP archive
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            for format_name, output_path in results.items():
                if output_path and output_path.exists():
                    # Add file to archive with relative path
                    arcname = output_path.name
                    zipf.write(output_path, arcname)

                    # Optionally remove original file
                    if self.config.security_level == SecurityLevel.PUBLIC:
                        output_path.unlink()

        logger.info(f"Archive created: {archive_path}")
        return archive_path

    def get_export_stats(self) -> Dict[str, Any]:
        """Get export statistics."""
        stats = self._export_stats.copy()

        # Calculate averages
        if stats["successful_exports"] > 0:
            stats["average_export_time"] = stats["total_time"] / stats["successful_exports"]
        else:
            stats["average_export_time"] = 0

        # Format timing by format
        if stats["format_times"]:
            stats["average_format_times"] = {
                fmt: sum(times) / len(times) if isinstance(times, list) else times
                for fmt, times in stats["format_times"].items()
            }

        return stats

    def validate_outputs(self, output_paths: Dict[str, Path]) -> Dict[str, bool]:
        """
        Validate generated output files.

        Args:
            output_paths: Dictionary of format to output path

        Returns:
            Dictionary of format to validation result
        """
        validation_results = {}

        for format_name, output_path in output_paths.items():
            if not output_path:
                validation_results[format_name] = False
                continue

            try:
                # Check file exists and has content
                if not output_path.exists():
                    validation_results[format_name] = False
                    continue

                file_size = output_path.stat().st_size
                if file_size == 0:
                    logger.warning(f"Empty {format_name} file: {output_path}")
                    validation_results[format_name] = False
                    continue

                # Format-specific validation based on file extension or format name
                file_ext = output_path.suffix.lower()
                check_format = format_name.lower()

                if file_ext == ".json" or "json" in check_format:
                    # Validate JSON structure
                    import json

                    with open(output_path, "r") as f:
                        json.load(f)

                elif file_ext == ".html" or "html" in check_format:
                    # Basic HTML validation
                    with open(output_path, "r") as f:
                        content = f.read()
                        if not ("<html" in content and "</html>" in content):
                            raise ValueError("Invalid HTML structure")

                elif file_ext == ".pdf" or "pdf" in check_format:
                    # Check PDF header
                    with open(output_path, "rb") as f:
                        header = f.read(4)
                        if header != b"%PDF":
                            raise ValueError("Invalid PDF header")

                validation_results[format_name] = True

            except Exception as e:
                logger.error(f"Validation failed for {format_name}: {str(e)}")
                validation_results[format_name] = False

        return validation_results
