#!/bin/bash

# Script to run Docker-based integration tests
# Implements ADR-012 Docker testing strategy

# shellcheck disable=SC2086  # Word splitting is intentional for test args
# shellcheck disable=SC1090  # Dynamic source files are intentional

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
COMPOSE_FILE="docker-compose.test.yml"
ENV_FILE=".env.test"
# MAX_WAIT_TIME=60  # Reserved for future timeout functionality
HEALTH_CHECK_INTERVAL=2

# Function to print colored messages
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to cleanup containers
cleanup() {
    print_message "$YELLOW" "Cleaning up test containers..."
    docker-compose -f $COMPOSE_FILE down -v --remove-orphans 2>/dev/null || true  # JUSTIFIED: Cleanup should always succeed even if containers don't exist
}

# Function to wait for services to be healthy
wait_for_healthy() {
    local service=$1
    local max_wait=$2
    local elapsed=0

    print_message "$YELLOW" "Waiting for $service to be healthy..."

    while [ "$elapsed" -lt "$max_wait" ]; do
        if docker-compose -f $COMPOSE_FILE ps | grep -q "$service.*healthy"; then
            print_message "$GREEN" "✓ $service is healthy"
            return 0
        fi
        sleep $HEALTH_CHECK_INTERVAL
        elapsed=$((elapsed + HEALTH_CHECK_INTERVAL))
        echo -n "."
    done

    print_message "$RED" "✗ $service failed to become healthy within ${max_wait}s"
    return 1
}

# Function to run tests
run_tests() {
    local test_type=$1
    shift
    local test_args="$*"

    case $test_type in
        "unit")
            print_message "$GREEN" "Running unit tests..."
            pytest tests/unit/ $test_args
            ;;
        "integration")
            print_message "$GREEN" "Running integration tests..."
            pytest tests/integration/ --base-url http://localhost:8000 $test_args
            ;;
        "bdd")
            print_message "$GREEN" "Running BDD tests..."
            behave tests/bdd/features/ $test_args
            ;;
        "performance")
            print_message "$GREEN" "Running performance tests..."
            pytest tests/performance/ --base-url http://localhost:8000 $test_args
            ;;
        "architecture")
            print_message "$GREEN" "Running architecture compliance tests..."
            pytest tests/architecture/ $test_args
            ;;
        "all")
            print_message "$GREEN" "Running all tests..."
            pytest tests/ --base-url http://localhost:8000 $test_args
            ;;
        *)
            print_message "$RED" "Unknown test type: $test_type"
            echo "Usage: $0 [unit|integration|bdd|performance|architecture|all] [pytest args]"
            exit 1
            ;;
    esac
}

# Main script
main() {
    local mode=${1:-"integration"}
    # JUSTIFIED: shift may fail if no arguments, but we want to continue with empty extra_args
    if [ $# -gt 0 ]; then
        shift
    fi
    local extra_args="$*"

    # Handle special modes
    case $mode in
        "local")
            # Run tests against local API (no Docker)
            print_message "$GREEN" "Running tests in local mode (no Docker)..."
            export TESTING=true
            # JUSTIFIED: Optional env file - continue with defaults if missing
            if [ -f "$ENV_FILE" ]; then
                source "$ENV_FILE"
            fi
            pytest tests/integration/ $extra_args
            exit $?
            ;;
        "cleanup")
            cleanup
            print_message "$GREEN" "✓ Cleanup complete"
            exit 0
            ;;
        "build")
            print_message "$YELLOW" "Building Docker images..."
            docker-compose -f $COMPOSE_FILE build
            print_message "$GREEN" "✓ Build complete"
            exit 0
            ;;
    esac

    # Trap to ensure cleanup on exit
    trap cleanup EXIT

    # Check prerequisites
    if ! command -v docker-compose &> /dev/null; then
        print_message "$RED" "docker-compose is not installed"
        exit 1
    fi

    if [ ! -f "$COMPOSE_FILE" ]; then
        print_message "$RED" "$COMPOSE_FILE not found"
        exit 1
    fi

    if [ ! -f "$ENV_FILE" ]; then
        print_message "$YELLOW" "Warning: $ENV_FILE not found, using defaults"
    fi

    # Clean up any existing containers
    cleanup

    # Start Docker environment
    print_message "$YELLOW" "Starting Docker test environment..."

    # Load test environment variables
    if [ -f "$ENV_FILE" ]; then
        set -a && source "$ENV_FILE" && set +a
    fi

    # Generate unique test run ID for parallel execution support
    TEST_RUN_ID="test_$(date +%s)_$$"
    export TEST_RUN_ID
    print_message "$YELLOW" "Test Run ID: $TEST_RUN_ID"

    # Start services
    START_TIME=$(date +%s)
    if ! docker-compose -f $COMPOSE_FILE up -d --build; then
        print_message "$RED" "Failed to start Docker environment"
        exit 1
    fi

    # Check startup time (should be under 30 seconds per ADR-012)
    STARTUP_TIME=$(($(date +%s) - START_TIME))
    if [ $STARTUP_TIME -gt 30 ]; then
        print_message "$YELLOW" "Warning: Startup took ${STARTUP_TIME}s (target: <30s)"
    else
        print_message "$GREEN" "✓ Startup completed in ${STARTUP_TIME}s"
    fi

    # Wait for services to be healthy
    HEALTH_START=$(date +%s)

    wait_for_healthy "db" 30
    wait_for_healthy "redis" 20
    wait_for_healthy "api" 45
    wait_for_healthy "celery" 30

    # Check health check time (should be under 60 seconds per ADR-012)
    HEALTH_TIME=$(($(date +%s) - HEALTH_START))
    if [ $HEALTH_TIME -gt 60 ]; then
        print_message "$YELLOW" "Warning: Health checks took ${HEALTH_TIME}s (target: <60s)"
    else
        print_message "$GREEN" "✓ All services healthy in ${HEALTH_TIME}s"
    fi

    # Verify API is responding
    print_message "$YELLOW" "Verifying API endpoint..."
    for i in {1..10}; do
        if curl -s http://localhost:8000/health > /dev/null 2>&1; then
            print_message "$GREEN" "✓ API is responding"
            break
        fi
        if [ "$i" -eq 10 ]; then
            print_message "$RED" "API is not responding"
            docker-compose -f $COMPOSE_FILE logs api
            exit 1
        fi
        sleep 2
    done

    # Run database migrations
    print_message "$YELLOW" "Running database migrations..."
    docker-compose -f $COMPOSE_FILE exec -T api alembic upgrade head

    # Load test fixtures (if needed)
    if [ -f "tests/fixtures/load_fixtures.py" ]; then
        print_message "$YELLOW" "Loading test fixtures..."
        docker-compose -f $COMPOSE_FILE exec -T api python tests/fixtures/load_fixtures.py
    fi

    # Run the requested tests
    print_message "$GREEN" "Environment ready! Running tests..."
    echo "----------------------------------------"

    run_tests "$mode" "$extra_args"
    TEST_EXIT_CODE=$?

    # Show logs if tests failed
    if [ $TEST_EXIT_CODE -ne 0 ]; then
        print_message "$YELLOW" "Test failed. Showing recent logs..."
        docker-compose -f $COMPOSE_FILE logs --tail=50
    fi

    # Cleanup is handled by trap
    exit $TEST_EXIT_CODE
}

# Show help if requested
if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
    cat << EOF
Docker Integration Testing Script
Usage: $0 [mode] [additional pytest args]

Modes:
  local         - Run tests against local API (no Docker)
  unit          - Run unit tests in Docker environment
  integration   - Run integration tests in Docker environment (default)
  bdd           - Run BDD tests using behave
  performance   - Run performance tests
  architecture  - Run architecture compliance tests
  all           - Run all test suites
  build         - Build Docker images only
  cleanup       - Clean up Docker containers

Examples:
  $0                           # Run integration tests
  $0 integration -v            # Run integration tests with verbose output
  $0 unit tests/unit/test_api  # Run specific unit test
  $0 local                     # Run tests without Docker
  $0 cleanup                   # Clean up containers

Environment Variables:
  TEST_RUN_ID          - Unique identifier for test run (auto-generated)
  PARALLEL_TEST_WORKER - Worker ID for parallel execution

This script implements ADR-012 Docker-based integration testing strategy.
EOF
    exit 0
fi

# Run main function
main "$@"
