// Main JavaScript for audit reports

// Initialize navigation
document.addEventListener('DOMContentLoaded', function() {
    initializeNavigation();
    initializeSmoothScrolling();
    initializeCharts();
    initializeTooltips();
    initializeFilters();
});

// Navigation highlighting
function initializeNavigation() {
    const nav = document.getElementById('report-nav');
    if (!nav) return;

    const links = nav.querySelectorAll('.nav-link');
    const sections = document.querySelectorAll('.report-section, .hero-section');

    // Update active link on scroll
    function updateActiveLink() {
        const scrollPos = window.scrollY + 100;

        sections.forEach(section => {
            const top = section.offsetTop;
            const height = section.offsetHeight;
            const id = section.getAttribute('id');

            if (scrollPos >= top && scrollPos < top + height) {
                links.forEach(link => {
                    link.classList.remove('active');
                    if (link.getAttribute('href') === `#${id}`) {
                        link.classList.add('active');
                    }
                });
            }
        });
    }

    window.addEventListener('scroll', updateActiveLink);
    updateActiveLink();
}

// Smooth scrolling for anchor links
function initializeSmoothScrolling() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                const offset = 100; // Account for fixed header
                const targetPos = target.offsetTop - offset;
                window.scrollTo({
                    top: targetPos,
                    behavior: 'smooth'
                });
            }
        });
    });
}

// Initialize all charts
function initializeCharts() {
    // Set default Chart.js options
    if (typeof Chart !== 'undefined') {
        Chart.defaults.font.family = getComputedStyle(document.documentElement)
            .getPropertyValue('--font-primary');
        Chart.defaults.color = getComputedStyle(document.documentElement)
            .getPropertyValue('--text-primary');
    }

    // Initialize custom chart types
    initializeGaugeCharts();
    initializeHeatmapCharts();
    initializeVelocityGauges();
}

// Custom gauge chart implementation
function initializeGaugeCharts() {
    const gaugeCharts = document.querySelectorAll('[data-chart-type="gauge"]');

    gaugeCharts.forEach(container => {
        const config = JSON.parse(container.dataset.chartConfig || '{}');
        if (config.type === 'custom-gauge') {
            createGaugeChart(container, config.data, config.options);
        }
    });
}

// Create gauge chart
function createGaugeChart(container, data, options) {
    const { value, min, max, label } = data;
    const { color, thresholds, backgroundColor } = options;

    // Create SVG gauge
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 200 120');
    svg.style.width = '100%';
    svg.style.height = 'auto';

    // Background arc
    const bgArc = createArc(100, 100, 80, 0, 180, backgroundColor || '#e0e0e0');
    svg.appendChild(bgArc);

    // Value arc
    const angle = ((value - min) / (max - min)) * 180;
    const valueArc = createArc(100, 100, 80, 0, angle, color);
    svg.appendChild(valueArc);

    // Center text
    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    text.setAttribute('x', '100');
    text.setAttribute('y', '90');
    text.setAttribute('text-anchor', 'middle');
    text.setAttribute('font-size', '24');
    text.setAttribute('font-weight', 'bold');
    text.setAttribute('fill', color);
    text.textContent = label;
    svg.appendChild(text);

    container.appendChild(svg);
}

// Create SVG arc
function createArc(cx, cy, radius, startAngle, endAngle, color) {
    const start = polarToCartesian(cx, cy, radius, endAngle);
    const end = polarToCartesian(cx, cy, radius, startAngle);
    const largeArcFlag = endAngle - startAngle <= 180 ? '0' : '1';

    const d = [
        'M', start.x, start.y,
        'A', radius, radius, 0, largeArcFlag, 0, end.x, end.y
    ].join(' ');

    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', d);
    path.setAttribute('fill', 'none');
    path.setAttribute('stroke', color);
    path.setAttribute('stroke-width', '15');
    path.setAttribute('stroke-linecap', 'round');

    return path;
}

// Convert polar to cartesian coordinates
function polarToCartesian(centerX, centerY, radius, angleInDegrees) {
    const angleInRadians = (angleInDegrees - 90) * Math.PI / 180.0;
    return {
        x: centerX + (radius * Math.cos(angleInRadians)),
        y: centerY + (radius * Math.sin(angleInRadians))
    };
}

// Initialize heatmap charts
function initializeHeatmapCharts() {
    const heatmaps = document.querySelectorAll('[data-chart-type="heatmap"]');

    heatmaps.forEach(container => {
        const config = JSON.parse(container.dataset.chartConfig || '{}');
        if (config.type === 'custom-heatmap') {
            createHeatmapChart(container, config.data, config.options);
        }
    });
}

// Create heatmap visualization
function createHeatmapChart(container, data, options) {
    const { labels, values, rawValues, details } = data;
    const { colorScale, showValues, tooltip } = options;

    // Create heatmap grid
    const grid = document.createElement('div');
    grid.className = 'heatmap-grid';
    grid.style.display = 'grid';
    grid.style.gridTemplateColumns = 'repeat(auto-fill, minmax(100px, 1fr))';
    grid.style.gap = '4px';

    labels.forEach((label, index) => {
        const cell = document.createElement('div');
        cell.className = 'heatmap-cell';
        cell.style.padding = '12px';
        cell.style.borderRadius = '4px';
        cell.style.backgroundColor = getHeatmapColor(values[index], colorScale);
        cell.style.color = values[index] > 50 ? 'white' : 'black';
        cell.style.textAlign = 'center';
        cell.style.cursor = 'pointer';
        cell.style.transition = 'transform 0.2s';

        // Add hover effect
        cell.addEventListener('mouseenter', () => {
            cell.style.transform = 'scale(1.05)';
        });
        cell.addEventListener('mouseleave', () => {
            cell.style.transform = 'scale(1)';
        });

        // Cell content
        const labelDiv = document.createElement('div');
        labelDiv.style.fontSize = '12px';
        labelDiv.style.marginBottom = '4px';
        labelDiv.textContent = label;
        cell.appendChild(labelDiv);

        if (showValues) {
            const valueDiv = document.createElement('div');
            valueDiv.style.fontSize = '16px';
            valueDiv.style.fontWeight = 'bold';
            valueDiv.textContent = values[index];
            cell.appendChild(valueDiv);
        }

        // Tooltip
        if (tooltip && tooltip.enabled && details && details[index]) {
            cell.title = formatTooltip(tooltip.format, {
                label: label,
                value: values[index],
                rawValue: rawValues ? rawValues[index] : values[index],
                detail: details[index]
            });
        }

        grid.appendChild(cell);
    });

    container.appendChild(grid);
}

// Get color for heatmap value
function getHeatmapColor(value, colorScale) {
    if (colorScale === 'Reds') {
        const intensity = value / 100;
        const r = Math.floor(255 * intensity);
        const g = Math.floor(255 * (1 - intensity) * 0.3);
        const b = Math.floor(255 * (1 - intensity) * 0.3);
        return `rgb(${r}, ${g}, ${b})`;
    }
    return '#666';
}

// Format tooltip content
function formatTooltip(format, data) {
    return format.replace(/\{(\w+(?:\.\w+)?)\}/g, (match, key) => {
        const keys = key.split('.');
        let value = data;
        for (const k of keys) {
            value = value[k];
            if (value === undefined) break;
        }
        return value !== undefined ? value : match;
    });
}

// Initialize velocity gauge charts
function initializeVelocityGauges() {
    const velocityGauges = document.querySelectorAll('[data-chart-type="velocity-gauge"]');

    velocityGauges.forEach(container => {
        const config = JSON.parse(container.dataset.chartConfig || '{}');
        if (config.type === 'custom-velocity-gauge') {
            createVelocityGauge(container, config.data, config.options);
        }
    });
}

// Create velocity gauge
function createVelocityGauge(container, data, options) {
    const { value, min, max, zones } = data;
    const { needle, labels } = options;

    // Create container
    const gauge = document.createElement('div');
    gauge.className = 'velocity-gauge';
    gauge.style.position = 'relative';
    gauge.style.width = '100%';
    gauge.style.paddingBottom = '60%';

    // Create SVG
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.style.position = 'absolute';
    svg.style.width = '100%';
    svg.style.height = '100%';
    svg.setAttribute('viewBox', '0 0 200 120');

    // Draw zones
    zones.forEach(zone => {
        const startAngle = ((zone.from - min) / (max - min)) * 180;
        const endAngle = ((zone.to - min) / (max - min)) * 180;
        const arc = createArc(100, 100, 70, startAngle, endAngle, zone.color);
        arc.setAttribute('stroke-width', '20');
        svg.appendChild(arc);
    });

    // Draw needle
    if (needle && needle.show) {
        const angle = ((value - min) / (max - min)) * 180;
        const needleEnd = polarToCartesian(100, 100, 60, angle);

        const needlePath = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        needlePath.setAttribute('x1', '100');
        needlePath.setAttribute('y1', '100');
        needlePath.setAttribute('x2', needleEnd.x);
        needlePath.setAttribute('y2', needleEnd.y);
        needlePath.setAttribute('stroke', needle.color || '#333');
        needlePath.setAttribute('stroke-width', '3');
        needlePath.setAttribute('stroke-linecap', 'round');
        svg.appendChild(needlePath);

        // Needle center
        const center = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        center.setAttribute('cx', '100');
        center.setAttribute('cy', '100');
        center.setAttribute('r', '5');
        center.setAttribute('fill', needle.color || '#333');
        svg.appendChild(center);
    }

    // Add value label
    if (labels && labels.show) {
        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        text.setAttribute('x', '100');
        text.setAttribute('y', '110');
        text.setAttribute('text-anchor', 'middle');
        text.setAttribute('font-size', '16');
        text.setAttribute('font-weight', 'bold');
        text.textContent = labels.format.replace('{value}', value);
        svg.appendChild(text);
    }

    gauge.appendChild(svg);
    container.appendChild(gauge);
}

// Initialize tooltips
function initializeTooltips() {
    // Add tooltip styles if not present
    if (!document.getElementById('tooltip-styles')) {
        const style = document.createElement('style');
        style.id = 'tooltip-styles';
        style.textContent = `
            .tooltip {
                position: absolute;
                background: rgba(0, 0, 0, 0.9);
                color: white;
                padding: 8px 12px;
                border-radius: 4px;
                font-size: 14px;
                pointer-events: none;
                z-index: 1000;
                opacity: 0;
                transition: opacity 0.2s;
            }
            .tooltip.show {
                opacity: 1;
            }
        `;
        document.head.appendChild(style);
    }

    // Create tooltip element
    const tooltip = document.createElement('div');
    tooltip.className = 'tooltip';
    document.body.appendChild(tooltip);

    // Add tooltip behavior to elements
    document.querySelectorAll('[data-tooltip]').forEach(element => {
        element.addEventListener('mouseenter', (e) => {
            tooltip.textContent = e.target.dataset.tooltip;
            tooltip.classList.add('show');
        });

        element.addEventListener('mousemove', (e) => {
            tooltip.style.left = e.pageX + 10 + 'px';
            tooltip.style.top = e.pageY + 10 + 'px';
        });

        element.addEventListener('mouseleave', () => {
            tooltip.classList.remove('show');
        });
    });
}

// Initialize filters
function initializeFilters() {
    // Risk level filters
    const filterButtons = document.querySelectorAll('.filter-button');
    const filterableItems = document.querySelectorAll('.filterable');

    filterButtons.forEach(button => {
        button.addEventListener('click', () => {
            const filter = button.dataset.filter;

            // Update active state
            filterButtons.forEach(btn => btn.classList.remove('active'));
            button.classList.add('active');

            // Filter items
            filterableItems.forEach(item => {
                if (filter === 'all' || item.dataset.riskLevel === filter) {
                    item.style.display = '';
                } else {
                    item.style.display = 'none';
                }
            });
        });
    });

    // Search functionality
    const searchInput = document.getElementById('search-input');
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            const searchTerm = e.target.value.toLowerCase();

            filterableItems.forEach(item => {
                const text = item.textContent.toLowerCase();
                if (text.includes(searchTerm)) {
                    item.style.display = '';
                } else {
                    item.style.display = 'none';
                }
            });
        });
    }
}

// Export functionality
window.exportReport = function(format) {
    const exportButton = document.querySelector(`[data-export="${format}"]`);
    if (exportButton) {
        exportButton.classList.add('loading');

        // Simulate export
        setTimeout(() => {
            exportButton.classList.remove('loading');
            alert(`Report exported as ${format.toUpperCase()}`);
        }, 1000);
    }
};

// Print functionality
window.printReport = function() {
    window.print();
};
