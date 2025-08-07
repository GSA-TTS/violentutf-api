#!/bin/bash

# Script to display ViolentUTF API credentials

# Detect if terminal supports colors
if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
    # Color codes
    RED=$(tput setaf 1)
    GREEN=$(tput setaf 2)
    YELLOW=$(tput setaf 3)
    CYAN=$(tput setaf 6)
    BOLD=$(tput bold)
    NC=$(tput sgr0)
else
    # No colors if terminal doesn't support them
    RED=''
    GREEN=''
    YELLOW=''
    CYAN=''
    BOLD=''
    NC=''
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}║${NC} ${BOLD}ViolentUTF API Credentials${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Check if credentials file exists
if [ -f "$SCRIPT_DIR/.admin_credentials" ]; then
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/.admin_credentials"

    echo -e "${GREEN}${BOLD}Admin Credentials:${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════${NC}"
    echo -e "  ${BOLD}Username:${NC}    ${ADMIN_USERNAME:-Not set}"
    echo -e "  ${BOLD}Password:${NC}    ${ADMIN_PASSWORD:-Not set}"
    echo -e "  ${BOLD}API Key:${NC}     ${ADMIN_API_KEY:-Not set}"
    echo -e "${YELLOW}══════════════════════════════════════════${NC}"
    echo ""

    # Service URLs
    echo -e "${CYAN}Service URLs:${NC}"
    echo "  • API:           http://localhost:8000"
    echo "  • API Docs:      http://localhost:8000/docs"
    echo "  • Health Check:  http://localhost:8000/api/v1/health"
    echo ""

    # Example commands
    echo -e "${CYAN}Example Commands:${NC}"
    echo ""
    echo "1. Test health endpoint:"
    echo "   curl http://localhost:8000/api/v1/health"
    echo ""
    echo "2. Login to get JWT token:"
    if [[ "${ADMIN_PASSWORD}" != *"GENERATED"* ]]; then
        echo "   curl -X POST http://localhost:8000/api/v1/auth/login \\"
        echo "     -H \"Content-Type: application/json\" \\"
        echo "     -d '{\"username\": \"${ADMIN_USERNAME}\", \"password\": \"${ADMIN_PASSWORD}\"}'"
    else
        echo "   curl -X POST http://localhost:8000/api/v1/auth/login \\"
        echo "     -H \"Content-Type: application/json\" \\"
        echo "     -d '{\"username\": \"admin\", \"password\": \"<your-password>\"}'"
    fi
    echo ""

else
    echo -e "${RED}✗${NC} No credentials found!"
    echo ""
    echo "Please run the setup script first:"
    echo "  ./setup_violentutf_enhanced.sh"
    echo ""
fi

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
