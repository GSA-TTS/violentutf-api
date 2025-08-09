// Main JavaScript for Architectural Audit Report

// Wait for DOM to be ready
document.addEventListener('DOMContentLoaded', function() {
    'use strict';

    // Initialize all components
    initializeNavigation();
    initializeScoreAnimation();
    initializeCharts();
    initializeInteractiveElements();
    initializeAccessibility();
});

// Navigation handling
function initializeNavigation() {
    const navLinks = document.querySelectorAll('.nav-link');
    const sections = document.querySelectorAll('section[id], div[id]');

    // Smooth scrolling for navigation links
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const targetId = this.getAttribute('href').substring(1);
            const targetSection = document.getElementById(targetId);

            if (targetSection) {
                targetSection.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });

                // Update URL without page jump
                history.pushState(null, null, '#' + targetId);
            }
        });
    });

    // Active section highlighting
    function updateActiveNav() {
        const scrollPosition = window.scrollY + 100;

        sections.forEach(section => {
            const top = section.offsetTop;
            const height = section.offsetHeight;
            const id = section.getAttribute('id');

            if (scrollPosition >= top && scrollPosition < top + height) {
                navLinks.forEach(link => {
                    link.classList.remove('active');
                    if (link.getAttribute('href') === '#' + id) {
                        link.classList.add('active');
                    }
                });
            }
        });
    }

    // Throttle scroll events
    let scrollTimer;
    window.addEventListener('scroll', function() {
        if (scrollTimer) {
            clearTimeout(scrollTimer);
        }
        scrollTimer = setTimeout(updateActiveNav, 100);
    });

    // Initial call
    updateActiveNav();
}

// Score circle animation
function initializeScoreAnimation() {
    const scoreCircle = document.querySelector('.score-circle');

    if (scoreCircle) {
        const score = parseFloat(scoreCircle.getAttribute('data-score') || '0');
        const progressCircle = scoreCircle.querySelector('.score-progress');

        if (progressCircle) {
            // Calculate stroke offset based on score
            const circumference = 2 * Math.PI * 90; // radius = 90
            const offset = circumference - (score / 100) * circumference;

            // Set initial state
            progressCircle.style.strokeDasharray = circumference;
            progressCircle.style.strokeDashoffset = circumference;

            // Trigger animation after a small delay
            setTimeout(() => {
                progressCircle.style.transition = 'stroke-dashoffset 1.5s ease-out';
                progressCircle.style.strokeDashoffset = offset;

                // Also set color based on score
                if (score < 50) {
                    progressCircle.style.stroke = 'var(--danger-color)';
                } else if (score < 70) {
                    progressCircle.style.stroke = 'var(--warning-color)';
                } else if (score < 85) {
                    progressCircle.style.stroke = 'var(--info-color)';
                } else {
                    progressCircle.style.stroke = 'var(--success-color)';
                }
            }, 100);

            // Animate the score number
            animateValue(scoreCircle.querySelector('.score-value'), 0, score, 1500);
        }
    }
}

// Animate numeric values
function animateValue(element, start, end, duration) {
    if (!element) return;

    const startTime = performance.now();
    const endTime = startTime + duration;

    function update() {
        const now = performance.now();
        const progress = Math.min((now - startTime) / duration, 1);

        // Ease out quad
        const easeProgress = 1 - (1 - progress) * (1 - progress);
        const value = start + (end - start) * easeProgress;

        element.textContent = value.toFixed(1) + '%';

        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }

    requestAnimationFrame(update);
}

// Initialize charts
function initializeCharts() {
    // Risk distribution chart
    const riskDistChart = document.getElementById('risk-distribution-chart');
    if (riskDistChart && typeof Chart !== 'undefined') {
        const ctx = riskDistChart.getContext('2d');

        // Get data from the page or use defaults
        const riskData = {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            values: [
                parseInt(document.querySelector('.risk-critical td:nth-child(2)')?.textContent || '0'),
                parseInt(document.querySelector('.risk-high td:nth-child(2)')?.textContent || '0'),
                parseInt(document.querySelector('.risk-medium td:nth-child(2)')?.textContent || '0'),
                parseInt(document.querySelector('.risk-low td:nth-child(2)')?.textContent || '0')
            ],
            colors: ['#f44336', '#ff5722', '#ff9800', '#4caf50']
        };

        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: riskData.labels,
                datasets: [{
                    data: riskData.values,
                    backgroundColor: riskData.colors,
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 15,
                            font: {
                                size: 12
                            }
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.parsed || 0;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                                return label + ': ' + value + ' (' + percentage + '%)';
                            }
                        }
                    }
                }
            }
        });
    }

    // Initialize other charts that might be dynamically added
    document.querySelectorAll('.chart-container canvas').forEach(canvas => {
        if (canvas.id && !canvas.chart) {
            initializeChartFromElement(canvas);
        }
    });
}

// Initialize chart from data attributes or inline configuration
function initializeChartFromElement(canvas) {
    const ctx = canvas.getContext('2d');
    const configScript = canvas.parentElement.querySelector('script[type="application/json"]');

    if (configScript) {
        try {
            const config = JSON.parse(configScript.textContent);
            canvas.chart = new Chart(ctx, config);
        } catch (e) {
            console.error('Failed to parse chart configuration:', e);
        }
    }
}

// Interactive elements
function initializeInteractiveElements() {
    // Collapsible sections
    document.querySelectorAll('.collapsible').forEach(element => {
        element.addEventListener('click', function() {
            this.classList.toggle('active');
            const content = this.nextElementSibling;
            if (content.style.maxHeight) {
                content.style.maxHeight = null;
            } else {
                content.style.maxHeight = content.scrollHeight + 'px';
            }
        });
    });

    // Copy to clipboard for code blocks
    document.querySelectorAll('pre code').forEach(block => {
        const button = document.createElement('button');
        button.className = 'copy-button';
        button.textContent = 'Copy';
        button.addEventListener('click', function() {
            navigator.clipboard.writeText(block.textContent).then(() => {
                button.textContent = 'Copied!';
                setTimeout(() => {
                    button.textContent = 'Copy';
                }, 2000);
            });
        });
        block.parentElement.appendChild(button);
    });

    // Table sorting
    document.querySelectorAll('table.sortable').forEach(table => {
        const headers = table.querySelectorAll('th');
        headers.forEach((header, index) => {
            header.style.cursor = 'pointer';
            header.addEventListener('click', () => sortTable(table, index));
        });
    });
}

// Table sorting function
function sortTable(table, column) {
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const isNumeric = rows.length > 0 && !isNaN(rows[0].cells[column].textContent);

    rows.sort((a, b) => {
        const aValue = a.cells[column].textContent;
        const bValue = b.cells[column].textContent;

        if (isNumeric) {
            return parseFloat(aValue) - parseFloat(bValue);
        }
        return aValue.localeCompare(bValue);
    });

    // Toggle sort direction
    if (table.sortColumn === column) {
        rows.reverse();
        table.sortColumn = -1;
    } else {
        table.sortColumn = column;
    }

    // Reappend rows
    rows.forEach(row => tbody.appendChild(row));
}

// Accessibility enhancements
function initializeAccessibility() {
    // Skip to main content link
    const skipLink = document.createElement('a');
    skipLink.href = '#main-content';
    skipLink.className = 'skip-link';
    skipLink.textContent = 'Skip to main content';
    document.body.insertBefore(skipLink, document.body.firstChild);

    // Keyboard navigation for interactive elements
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            // Close any open modals or dropdowns
            document.querySelectorAll('.modal.open').forEach(modal => {
                modal.classList.remove('open');
            });
        }
    });

    // Focus management
    const focusableElements = 'a[href], button, input, select, textarea, [tabindex]:not([tabindex="-1"])';
    const firstFocusable = document.querySelector(focusableElements);

    // Trap focus in modals
    document.querySelectorAll('.modal').forEach(modal => {
        const focusableContent = modal.querySelectorAll(focusableElements);
        const firstFocusableElement = focusableContent[0];
        const lastFocusableElement = focusableContent[focusableContent.length - 1];

        modal.addEventListener('keydown', function(e) {
            if (e.key === 'Tab') {
                if (e.shiftKey) {
                    if (document.activeElement === firstFocusableElement) {
                        lastFocusableElement.focus();
                        e.preventDefault();
                    }
                } else {
                    if (document.activeElement === lastFocusableElement) {
                        firstFocusableElement.focus();
                        e.preventDefault();
                    }
                }
            }
        });
    });
}

// Utility functions
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function throttle(func, limit) {
    let inThrottle;
    return function(...args) {
        if (!inThrottle) {
            func.apply(this, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

// Export functions for external use
window.reportUtils = {
    animateValue,
    sortTable,
    debounce,
    throttle
};
