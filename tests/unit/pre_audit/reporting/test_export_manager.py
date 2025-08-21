"""
Unit tests for export manager with parallel processing.

Tests coordinated multi-format export capabilities.
"""

import asyncio
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from tools.pre_audit.reporting import ExportManager, ReportConfig, SecurityLevel, ValidationError


class TestExportManager:
    """Test suite for ExportManager class."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def config(self, temp_dir):
        """Create test configuration."""
        return ReportConfig(output_dir=temp_dir, enable_parallel_export=True, export_formats=["html", "json", "pdf"])

    @pytest.fixture
    def manager(self, config):
        """Create ExportManager instance."""
        return ExportManager(config)

    @pytest.fixture
    def sample_audit_data(self):
        """Create sample audit data."""
        return {
            "audit_metadata": {"total_files_analyzed": 100, "repository_path": "/test/repo"},
            "overall_compliance_score": 85.0,
            "all_violations": [],
        }

    def test_export_manager_initialization(self, manager):
        """Test ExportManager initialization."""
        # PDF might be removed if ReportLab not installed
        assert "html" in manager.export_formats
        assert "json" in manager.export_formats
        assert "html" in manager.generators
        assert "json" in manager.generators
        # At least HTML and JSON should be available
        assert len(manager.generators) >= 2

    def test_export_manager_handles_missing_pdf(self, temp_dir):
        """Test that missing PDF support is handled gracefully."""
        config = ReportConfig(output_dir=temp_dir, export_formats=["html", "json", "pdf"])

        with patch(
            "tools.pre_audit.reporting.export_manager.PDFReportGenerator",
            side_effect=ImportError("ReportLab not installed"),
        ):
            manager = ExportManager(config)

            assert "pdf" not in manager.export_formats
            assert "pdf" not in manager.generators

    def test_export_all_sequential(self, manager, sample_audit_data, temp_dir):
        """Test sequential export of all formats."""
        # Disable parallel export
        manager.config.enable_parallel_export = False

        # Mock generators
        for format_name in ["html", "json", "pdf"]:
            if format_name in manager.generators:
                mock_gen = MagicMock()
                mock_gen.generate.return_value = temp_dir / f"report.{format_name}"
                manager.generators[format_name] = mock_gen

        results = manager.export_all(sample_audit_data)

        # Check results
        assert "html" in results
        assert "json" in results
        assert all(isinstance(p, Path) for p in results.values() if p)

        # Verify generators were called
        for format_name, generator in manager.generators.items():
            if hasattr(generator, "generate"):
                generator.generate.assert_called_once()

    def test_export_all_parallel(self, manager, sample_audit_data, temp_dir):
        """Test parallel export of all formats."""
        # Mock generators with delays to test parallelism
        delays = {"html": 0.1, "json": 0.1, "pdf": 0.1}

        for format_name in manager.generators:
            mock_gen = MagicMock()

            def make_generate(fmt):
                def generate(data):
                    time.sleep(delays.get(fmt, 0.1))
                    return temp_dir / f"report.{fmt}"

                return generate

            mock_gen.generate.side_effect = make_generate(format_name)
            manager.generators[format_name] = mock_gen

        # Time the parallel export
        start_time = time.time()
        results = manager.export_all(sample_audit_data)
        elapsed = time.time() - start_time

        # Should be faster than sequential (0.3s)
        assert elapsed < 0.25  # Allow some overhead
        assert len(results) >= 2

    def test_export_all_handles_validation_error(self, manager):
        """Test that validation errors are handled properly."""
        # The current implementation is robust and handles missing fields gracefully
        # Test with minimal data to ensure it doesn't crash
        minimal_data = {"invalid": "data"}

        # The system should handle this gracefully
        results = manager.export_all(minimal_data)

        # All exports should complete successfully with default values
        assert all(path is not None for path in results.values())
        assert len(results) >= 1  # At least one format exported

        # For actual validation errors, we need data that fails size limits
        import json

        huge_data = {"all_violations": [{"data": "x" * 1000000} for _ in range(100)]}

        # This should fail due to size constraints
        with pytest.raises(ValidationError, match="exceeds maximum allowed size"):
            manager.export_all(huge_data)

    def test_export_all_handles_generator_error(self, manager, sample_audit_data):
        """Test handling of generator errors."""
        # Mock the HTML generator to fail
        with patch.object(
            manager.generators.get("html", MagicMock()), "generate", side_effect=Exception("Generator failed")
        ):
            results = manager.export_all(sample_audit_data)

            # HTML should be None, others should succeed
            assert results.get("html") is None
            assert "json" in results

    def test_export_single_format(self, manager, sample_audit_data, temp_dir):
        """Test exporting a single format."""
        # Mock generator
        mock_gen = MagicMock()
        mock_gen.generate.return_value = temp_dir / "report.json"
        manager.generators["json"] = mock_gen

        output_path, export_time = manager._export_single_format("json", sample_audit_data)

        assert output_path == temp_dir / "report.json"
        assert export_time > 0
        mock_gen.generate.assert_called_once_with(sample_audit_data)

    def test_export_single_format_handles_error(self, manager, sample_audit_data):
        """Test single format export error handling."""
        # Mock the generator to fail
        with patch.object(manager.generators["json"], "generate", side_effect=Exception("Failed")):
            output_path, export_time = manager._export_single_format("json", sample_audit_data)

            assert output_path is None
            assert export_time > 0

    @pytest.mark.asyncio
    async def test_export_all_async(self, manager, sample_audit_data, temp_dir):
        """Test asynchronous export."""
        # Mock generators
        for format_name in manager.generators:
            mock_gen = MagicMock()
            mock_gen.generate.return_value = temp_dir / f"report.{format_name}"
            manager.generators[format_name] = mock_gen

        results = await manager.export_all_async(sample_audit_data)

        assert len(results) >= 2
        assert all(isinstance(p, (Path, type(None))) for p in results.values())

    def test_export_to_archive(self, manager, sample_audit_data, temp_dir):
        """Test archive creation."""
        # Create mock report files
        report_files = {}
        for fmt in ["html", "json"]:
            report_file = temp_dir / f"report.{fmt}"
            report_file.write_text(f"Test {fmt} content")
            report_files[fmt] = report_file

        # Mock export_all to return these files
        with patch.object(manager, "export_all", return_value=report_files):
            archive_path = manager.export_to_archive(sample_audit_data)

        assert archive_path.exists()
        assert archive_path.suffix == ".zip"
        assert "audit_reports_" in archive_path.name

        # Verify archive contents
        import zipfile

        with zipfile.ZipFile(archive_path, "r") as zf:
            names = zf.namelist()
            assert "report.html" in names
            assert "report.json" in names

    def test_export_to_archive_custom_name(self, manager, sample_audit_data, temp_dir):
        """Test archive creation with custom name."""
        with patch.object(manager, "export_all", return_value={}):
            archive_path = manager.export_to_archive(sample_audit_data, archive_name="custom_report.zip")

        assert archive_path.name == "custom_report.zip"

    def test_export_to_archive_removes_originals_public(self, manager, sample_audit_data, temp_dir):
        """Test that original files are removed for public security level."""
        manager.config.security_level = SecurityLevel.PUBLIC

        # Create mock report file
        report_file = temp_dir / "report.html"
        report_file.write_text("Test content")

        with patch.object(manager, "export_all", return_value={"html": report_file}):
            archive_path = manager.export_to_archive(sample_audit_data)

        # Original file should be removed
        assert not report_file.exists()
        assert archive_path.exists()

    def test_get_export_stats(self, manager, sample_audit_data):
        """Test export statistics."""
        # Disable parallel export to ensure sequential is called
        manager.config.enable_parallel_export = False

        # Perform some exports
        with patch.object(manager, "_export_sequential", return_value={"html": Path("test.html")}):
            manager.export_all(sample_audit_data)

        stats = manager.get_export_stats()

        assert stats["total_exports"] == 1
        assert stats["successful_exports"] == 1
        assert "average_export_time" in stats
        assert stats["average_export_time"] >= 0

    def test_validate_outputs(self, manager, temp_dir):
        """Test output file validation."""
        # Create test files
        valid_html = temp_dir / "valid.html"
        valid_html.write_text("<html><body>Test</body></html>")

        valid_json = temp_dir / "valid.json"
        valid_json.write_text('{"test": "data"}')

        invalid_json = temp_dir / "invalid.json"
        invalid_json.write_text("not json")

        empty_file = temp_dir / "empty.pdf"
        empty_file.write_text("")

        results = manager.validate_outputs(
            {
                "html": valid_html,
                "json": valid_json,
                "invalid_json": invalid_json,
                "empty": empty_file,
                "missing": temp_dir / "missing.txt",
            }
        )

        assert results["html"] is True
        assert results["json"] is True
        assert results["invalid_json"] is False
        assert results["empty"] is False
        assert results["missing"] is False

    def test_validate_outputs_pdf(self, manager, temp_dir):
        """Test PDF validation."""
        # Create valid PDF (minimal header)
        valid_pdf = temp_dir / "valid.pdf"
        valid_pdf.write_bytes(b"%PDF-1.4\n")

        # Create invalid PDF
        invalid_pdf = temp_dir / "invalid.pdf"
        invalid_pdf.write_text("Not a PDF")

        results = manager.validate_outputs({"valid_pdf": valid_pdf, "invalid_pdf": invalid_pdf})

        assert results["valid_pdf"] is True
        assert results["invalid_pdf"] is False

    def test_export_stats_with_formats(self, manager):
        """Test export statistics with format timing."""
        manager._export_stats = {
            "total_exports": 2,
            "successful_exports": 2,
            "failed_exports": 0,
            "total_time": 1.0,
            "format_times": {"html": 0.4, "json": 0.3, "pdf": 0.3},
        }

        stats = manager.get_export_stats()

        assert stats["average_export_time"] == 0.5
        assert "average_format_times" in stats
        assert stats["average_format_times"]["html"] == 0.4
