#!/bin/bash

# ViolentUTF API Endpoints Reference
# Quick reference for the new async task and scan management endpoints

# Color codes for output
if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
    GREEN=$(tput setaf 2)
    YELLOW=$(tput setaf 3)
    BLUE=$(tput setaf 4)
    CYAN=$(tput setaf 6)
    NC=$(tput sgr0) # No Color
    BOLD=$(tput bold)
else
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    NC=''
    BOLD=''
fi

echo ""
echo "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo "${CYAN}${BOLD}║                ViolentUTF API Endpoints Reference            ║${NC}"
echo "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo "${GREEN}${BOLD}🔗 Service URLs:${NC}"
echo "  ${BLUE}API Documentation:${NC} http://localhost:8000/docs"
echo "  ${BLUE}API Base URL:${NC}      http://localhost:8000/api/v1"
echo "  ${BLUE}Flower Dashboard:${NC}  http://localhost:5555 (Celery monitoring)"
echo "  ${BLUE}Health Check:${NC}      http://localhost:8000/api/v1/health"
echo ""

echo "${GREEN}${BOLD}🔧 Task Management Endpoints:${NC}"
echo "  ${YELLOW}GET${NC}    /api/v1/tasks              ${BLUE}# List tasks with filtering${NC}"
echo "  ${YELLOW}POST${NC}   /api/v1/tasks              ${BLUE}# Create new task${NC}"
echo "  ${YELLOW}GET${NC}    /api/v1/tasks/{id}         ${BLUE}# Get task status (ADR-007 polling)${NC}"
echo "  ${YELLOW}PUT${NC}    /api/v1/tasks/{id}         ${BLUE}# Update task${NC}"
echo "  ${YELLOW}DELETE${NC} /api/v1/tasks/{id}         ${BLUE}# Delete task (soft delete)${NC}"
echo "  ${YELLOW}POST${NC}   /api/v1/tasks/{id}/execute ${BLUE}# Execute task (202 Accepted)${NC}"
echo "  ${YELLOW}POST${NC}   /api/v1/tasks/{id}/cancel  ${BLUE}# Cancel running task${NC}"
echo "  ${YELLOW}POST${NC}   /api/v1/tasks/{id}/retry   ${BLUE}# Retry failed task${NC}"
echo "  ${YELLOW}GET${NC}    /api/v1/tasks/{id}/results ${BLUE}# Get task results${NC}"
echo "  ${YELLOW}POST${NC}   /api/v1/tasks/bulk         ${BLUE}# Bulk operations${NC}"
echo "  ${YELLOW}GET${NC}    /api/v1/tasks/stats        ${BLUE}# Task statistics${NC}"
echo ""

echo "${GREEN}${BOLD}🛡️  Security Scan Endpoints:${NC}"
echo "  ${YELLOW}GET${NC}    /api/v1/scans              ${BLUE}# List scans with filtering${NC}"
echo "  ${YELLOW}POST${NC}   /api/v1/scans              ${BLUE}# Create & execute scan (202 Accepted)${NC}"
echo "  ${YELLOW}GET${NC}    /api/v1/scans/{id}         ${BLUE}# Get scan status (ADR-007 polling)${NC}"
echo "  ${YELLOW}PUT${NC}    /api/v1/scans/{id}         ${BLUE}# Update scan${NC}"
echo "  ${YELLOW}DELETE${NC} /api/v1/scans/{id}         ${BLUE}# Delete scan (soft delete)${NC}"
echo "  ${YELLOW}POST${NC}   /api/v1/scans/{id}/execute ${BLUE}# Execute scan${NC}"
echo "  ${YELLOW}POST${NC}   /api/v1/scans/{id}/cancel  ${BLUE}# Cancel running scan${NC}"
echo "  ${YELLOW}GET${NC}    /api/v1/scans/{id}/findings ${BLUE}# Get scan findings${NC}"
echo "  ${YELLOW}GET${NC}    /api/v1/scans/{id}/reports  ${BLUE}# Get scan reports${NC}"
echo "  ${YELLOW}GET${NC}    /api/v1/scans/stats        ${BLUE}# Scan statistics${NC}"
echo ""

echo "${GREEN}${BOLD}🔑 Authentication:${NC}"
echo "  ${BLUE}All endpoints require authentication via Bearer token${NC}"
echo "  ${BLUE}Get token via:${NC} POST /api/v1/auth/login"
echo ""

echo "${GREEN}${BOLD}📊 Key Features:${NC}"
echo "  ${CYAN}✓${NC} ADR-007 compliant HTTP polling for task status"
echo "  ${CYAN}✓${NC} 202 Accepted responses for async operations"
echo "  ${CYAN}✓${NC} Webhook notifications support"
echo "  ${CYAN}✓${NC} Comprehensive filtering and pagination"
echo "  ${CYAN}✓${NC} CVSS scoring for security findings"
echo "  ${CYAN}✓${NC} Real-time progress tracking"
echo "  ${CYAN}✓${NC} Bulk operations support"
echo "  ${CYAN}✓${NC} Soft delete and audit trails"
echo ""

echo "${GREEN}${BOLD}🔄 Example Usage:${NC}"
echo "${BLUE}# Get authentication token${NC}"
printf 'curl -X POST http://localhost:8000/api/v1/auth/login \\\n'
printf '  -H "Content-Type: application/json" \\\n'
printf '  -d %s\n' ''"'"'{"username": "admin", "password": "your-password"}'"'"''
echo ""
echo "${BLUE}# Create a security scan${NC}"
printf 'curl -X POST http://localhost:8000/api/v1/scans \\\n'
printf '  -H "Content-Type: application/json" \\\n'
printf '  -H "Authorization: Bearer YOUR_TOKEN" \\\n'
printf '  -d %s\n' ''"'"'{"name": "Test Scan", "scan_type": "PYRIT_ORCHESTRATOR", "target_config": {"endpoint": "https://example.com"}}'"'"''
echo ""
echo "${BLUE}# Check scan status (ADR-007 polling)${NC}"
printf 'curl -H "Authorization: Bearer YOUR_TOKEN" \\\n'
printf '  http://localhost:8000/api/v1/scans/{scan_id}\n'
echo ""

echo "${GREEN}${BOLD}📈 Monitoring:${NC}"
echo "  ${BLUE}Flower Dashboard:${NC} http://localhost:5555"
echo "  ${BLUE}Service Status:${NC}   ./setup_violentutf.sh --status"
echo "  ${BLUE}View Logs:${NC}        ./setup_violentutf.sh --logs"
echo ""

echo "${CYAN}For complete API documentation, visit: ${BOLD}http://localhost:8000/docs${NC}"
echo ""
