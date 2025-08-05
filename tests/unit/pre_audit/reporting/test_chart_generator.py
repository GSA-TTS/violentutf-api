"""
Unit tests for chart generation module.

Tests Chart.js configuration generation for various chart types.
"""

import json

import pytest

from tools.pre_audit.reporting.visualization import ChartGenerator, ChartType


class TestChartGenerator:
    """Test suite for ChartGenerator class."""

    @pytest.fixture
    def generator(self):
        """Create ChartGenerator instance."""
        return ChartGenerator()

    # Test Pie Chart Generation
    def test_generate_pie_chart_basic(self, generator):
        """Test basic pie chart generation."""
        data = {
            "labels": ["Critical", "High", "Medium", "Low"],
            "values": [5, 10, 20, 15],
            "colors": ["#d32f2f", "#f57c00", "#fbc02d", "#388e3c"],
        }

        config = generator.generate_pie_chart(data, title="Risk Distribution")

        assert config["type"] == "pie"
        assert len(config["data"]["labels"]) == 4
        assert config["data"]["datasets"][0]["data"] == [5, 10, 20, 15]
        assert len(config["data"]["datasets"][0]["backgroundColor"]) == 4
        assert config["options"]["plugins"]["title"]["text"] == "Risk Distribution"

    def test_generate_pie_chart_label_encoding(self, generator):
        """Test that labels are properly encoded."""
        data = {"labels": ["<script>alert('XSS')</script>", "Normal Label"], "values": [50, 50]}

        config = generator.generate_pie_chart(data)

        # Labels should be encoded
        assert "<script>" not in config["data"]["labels"][0]
        assert "Normal Label" in config["data"]["labels"][1]

    def test_generate_pie_chart_default_colors(self, generator):
        """Test default color assignment."""
        data = {"labels": ["A", "B", "C", "D", "E"], "values": [1, 2, 3, 4, 5]}

        config = generator.generate_pie_chart(data)

        colors = config["data"]["datasets"][0]["backgroundColor"]
        assert len(colors) == 5
        # Should use default colors
        assert colors[0] == generator.DEFAULT_COLORS[0]

    # Test Bar Chart Generation
    def test_generate_bar_chart_vertical(self, generator):
        """Test vertical bar chart generation."""
        data = {
            "labels": ["Jan", "Feb", "Mar", "Apr"],
            "values": [10, 20, 30, 25],
            "color": "#1976d2",
            "label": "Violations",
        }

        config = generator.generate_bar_chart(data, title="Monthly Violations")

        assert config["type"] == "bar"
        assert config["data"]["datasets"][0]["label"] == "Violations"
        assert config["data"]["datasets"][0]["backgroundColor"] == "#1976d2"
        assert config["options"]["scales"]["y"]["beginAtZero"] is True

    def test_generate_bar_chart_horizontal(self, generator):
        """Test horizontal bar chart generation."""
        data = {"labels": ["File 1", "File 2", "File 3"], "values": [15, 25, 10]}

        config = generator.generate_bar_chart(data, horizontal=True)

        assert config["type"] == "horizontalBar"
        assert config["options"]["indexAxis"] == "y"

    # Test Line Chart Generation
    def test_generate_line_chart_single_dataset(self, generator):
        """Test line chart with single dataset."""
        data = {
            "labels": ["Week 1", "Week 2", "Week 3", "Week 4"],
            "datasets": [{"label": "Compliance Score", "data": [70, 75, 80, 85], "color": "#4caf50"}],
        }

        config = generator.generate_line_chart(data, title="Compliance Trend")

        assert config["type"] == "line"
        assert len(config["data"]["datasets"]) == 1
        assert config["data"]["datasets"][0]["borderColor"] == "#4caf50"
        assert config["data"]["datasets"][0]["tension"] == 0.1

    def test_generate_line_chart_multiple_datasets(self, generator):
        """Test line chart with multiple datasets."""
        data = {
            "labels": ["Q1", "Q2", "Q3", "Q4"],
            "datasets": [{"label": "Critical", "data": [5, 3, 2, 1]}, {"label": "High", "data": [10, 8, 6, 4]}],
            "xLabel": "Quarter",
            "yLabel": "Count",
        }

        config = generator.generate_line_chart(data)

        assert len(config["data"]["datasets"]) == 2
        assert config["options"]["scales"]["x"]["title"]["text"] == "Quarter"
        assert config["options"]["scales"]["y"]["title"]["text"] == "Count"

    # Test Gauge Chart Generation
    def test_generate_gauge_chart(self, generator):
        """Test gauge chart generation."""
        config = generator.generate_gauge_chart(
            value=75, min_value=0, max_value=100, thresholds={"critical": 50, "warning": 70, "good": 85}
        )

        assert config["type"] == "custom-gauge"
        assert config["data"]["value"] == 75
        assert config["data"]["label"] == "75.0%"
        assert config["options"]["thresholds"]["warning"] == 70
        # Color should be orange (between warning and good)
        assert config["options"]["color"] == generator.TREND_COLORS["stable"]

    def test_gauge_color_selection(self, generator):
        """Test gauge color based on thresholds."""
        test_cases = [
            (95, generator.RISK_COLORS["low"]),  # > 90 (good)
            (85, generator.TREND_COLORS["stable"]),  # 80-90 (warning)
            (65, generator.RISK_COLORS["high"]),  # 60-80 (critical)
            (45, generator.RISK_COLORS["critical"]),  # < 60
        ]

        for value, expected_color in test_cases:
            config = generator.generate_gauge_chart(value)
            assert config["options"]["color"] == expected_color

    # Test Radar Chart Generation
    def test_generate_radar_chart(self, generator):
        """Test radar chart generation."""
        data = {
            "labels": ["Security", "Performance", "Maintainability", "Reliability"],
            "datasets": [{"label": "Current", "data": [70, 85, 60, 90], "color": "#1976d2"}],
            "maxValue": 100,
            "stepSize": 20,
        }

        config = generator.generate_radar_chart(data, title="Quality Metrics")

        assert config["type"] == "radar"
        assert config["options"]["scales"]["r"]["max"] == 100
        assert config["options"]["scales"]["r"]["ticks"]["stepSize"] == 20
        assert config["data"]["datasets"][0]["pointBorderColor"] == "#fff"

    # Test Risk Distribution Chart
    def test_generate_risk_distribution_chart(self, generator):
        """Test specialized risk distribution chart."""
        risk_data = {"critical": 5, "high": 10, "medium": 20, "low": 15, "minimal": 0}  # Should be excluded

        config = generator.generate_risk_distribution_chart(risk_data)

        assert config["type"] == "doughnut"
        assert len(config["data"]["labels"]) == 4  # minimal excluded
        assert "Critical" in config["data"]["labels"]
        assert config["data"]["datasets"][0]["backgroundColor"][0] == generator.RISK_COLORS["critical"]

    # Test Doughnut Chart Generation
    def test_generate_doughnut_chart(self, generator):
        """Test doughnut chart generation."""
        data = {"labels": ["Improving", "Stable", "Degrading"], "values": [30, 50, 20]}

        config = generator.generate_doughnut_chart(data, title="Trends")

        assert config["type"] == "doughnut"
        assert config["options"]["cutout"] == "60%"
        # Should have same data as pie chart
        assert config["data"]["labels"] == ["Improving", "Stable", "Degrading"]

    # Test Chart Container Creation
    def test_create_chart_container(self, generator):
        """Test chart container creation with HTML and JavaScript."""
        chart_config = {"type": "pie", "data": {"labels": ["A", "B"], "values": [50, 50]}}

        container = generator.create_chart_container(chart_config)

        assert "id" in container
        assert "html" in container
        assert "script" in container
        assert "config" in container

        # Check HTML contains canvas with ID
        assert f'id="{container["id"]}"' in container["html"]
        assert "chart-container" in container["html"]

        # Check script creates chart
        assert f"getElementById('{container['id']}')" in container["script"]
        assert "new Chart(" in container["script"]

    def test_create_chart_container_custom_id(self, generator):
        """Test chart container with custom ID."""
        chart_config = {"type": "bar", "data": {}}

        container = generator.create_chart_container(chart_config, container_id="my-chart")

        assert container["id"] == "my-chart"
        assert 'id="my-chart"' in container["html"]

    # Test Helper Methods
    def test_encode_labels(self, generator):
        """Test label encoding."""
        labels = ["<script>", "Normal", 123, None]

        encoded = generator._encode_labels(labels)

        assert len(encoded) == 4
        assert all(isinstance(l, str) for l in encoded)
        assert "<script>" not in encoded[0]
        assert encoded[1] == "Normal"
        assert encoded[2] == "123"
        assert encoded[3] == "None"

    def test_get_colors_custom(self, generator):
        """Test custom color assignment."""
        custom_colors = ["#ff0000", "#00ff00", "#0000ff"]

        colors = generator._get_colors(custom_colors, 2)

        assert colors == ["#ff0000", "#00ff00"]

    def test_get_colors_default_cycling(self, generator):
        """Test default color cycling for large datasets."""
        colors = generator._get_colors(None, 20)

        assert len(colors) == 20
        # Should cycle through default colors
        assert colors[0] == colors[12]  # 12 is the number of default colors
        assert colors[1] == colors[13]

    def test_get_percentage_tooltip(self, generator):
        """Test percentage tooltip function generation."""
        tooltip_func = generator._get_percentage_tooltip()

        assert "function(context)" in tooltip_func
        assert "percentage" in tooltip_func
        assert "toFixed(1)" in tooltip_func
