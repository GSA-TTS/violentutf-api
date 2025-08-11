Feature: Core Docker Test Environment Setup (US-101)
  As a developer
  I want Docker Compose configurations for testing
  So that I can run isolated integration tests without affecting my local development environment

  Background:
    Given the docker-compose.test.yml file exists in the project root

  @critical @adr-012
  Scenario: Docker test environment initialization
    Given the docker-compose.test.yml file exists
    When I run "docker-compose -f docker-compose.test.yml up -d"
    Then all services must start within 30 seconds
    And all health checks must pass within 60 seconds
    And the API endpoint must respond at http://localhost:8000/health

  @critical @isolation
  Scenario: Test environment isolation
    Given the Docker test environment is running
    When I check the database and Redis connections
    Then the test PostgreSQL must use database name "testdb"
    And the test Redis must use a separate instance on port 6379
    And no production data must be accessible

  @critical @asr-1
  Scenario: Clean environment startup
    Given no previous test containers are running
    When I start the Docker test environment
    Then each container must start with a clean state
    And no data from previous test runs must persist
    And all volumes must be ephemeral by default

  @security
  Scenario: Test credentials isolation
    Given the Docker test environment configuration
    When I examine the environment variables
    Then test credentials must be different from production
    And no production secrets must be present
    And test API keys must be clearly marked as test data

  @performance
  Scenario: Resource constraints for test environment
    Given the Docker test environment is configured
    When I check resource limits
    Then each container must have memory limits defined
    And CPU limits must prevent resource exhaustion
    And total resource usage must be sustainable for CI/CD
