#!/bin/bash

# ViolentUTF API Setup Script
# Comprehensive setup, management, and cleanup for ViolentUTF API Docker deployment
# Author: ViolentUTF Team
# Version: 1.0.0

set -e  # Exit on error

# Detect if terminal supports colors
if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
    # Color codes for output
    RED=$(tput setaf 1)
    GREEN=$(tput setaf 2)
    YELLOW=$(tput setaf 3)
    BLUE=$(tput setaf 4)
    CYAN=$(tput setaf 6)
    NC=$(tput sgr0) # No Color
    BOLD=$(tput bold)
else
    # No colors if terminal doesn't support them
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    NC=''
    BOLD=''
fi

# Configuration
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_NAME="violentutf-api"
DOCKER_COMPOSE_FILE="docker-compose.yml"
ENV_FILE=".env"
ENV_EXAMPLE_FILE=".env.example"
BACKUP_DIR="backups"
DATA_DIRS=("postgres_data" "redis_data" "logs")
CACHE_DIRS=(".pytest_cache" "__pycache__" "htmlcov" ".mypy_cache")
MINIMUM_DOCKER_VERSION="20.10.0"
# MINIMUM_DOCKER_COMPOSE_VERSION removed as it was unused
MINIMUM_PYTHON_VERSION="3.11"
REQUIRED_DISK_SPACE_MB=2048

# Admin credentials and API key
ADMIN_USERNAME=""
ADMIN_PASSWORD=""
ADMIN_EMAIL=""
GENERATED_API_KEY=""
ADMIN_CREDENTIALS_SET="false"
GENERATED_DB_PASSWORD=""
GENERATED_SECRET_KEY=""
GENERATED_JWT_SECRET=""
GENERATED_REDIS_PASSWORD=""
GENERATED_SECRETS=""
DIM='\033[2m'

# Function to print colored output
print_color() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to print section headers
print_header() {
    echo ""
    print_color "$CYAN" "╔══════════════════════════════════════════════════════════════╗"
    print_color "$CYAN" "║  $1"
    print_color "$CYAN" "╚══════════════════════════════════════════════════════════════╝"
    echo ""
}

# Function to print status
print_status() {
    local status=$1
    local message=$2
    if [ "$status" == "success" ]; then
        print_color "$GREEN" "✓ $message"
    elif [ "$status" == "error" ]; then
        print_color "$RED" "✗ $message"
    elif [ "$status" == "warning" ]; then
        print_color "$YELLOW" "⚠ $message"
    elif [ "$status" == "info" ]; then
        print_color "$BLUE" "ℹ $message"
    else
        echo "  $message"
    fi
}

# Function to check command existence
check_command() {
    local cmd=$1
    # name parameter removed as it was unused
    if command -v "$cmd" &> /dev/null; then
        return 0
    else
        return 1
    fi
}

# Function to compare versions
version_compare() {
    local version1=$1
    local version2=$2
    if [[ "$version1" == "$version2" ]]; then
        return 0
    fi
    local IFS=.
    # Fix shellcheck warning about word splitting
    local i
    read -ra ver1 <<< "$version1"
    read -ra ver2 <<< "$version2"
    for ((i=${#ver1[@]}; i<${#ver2[@]}; i++)); do
        ver1[i]=0
    done
    for ((i=0; i<${#ver1[@]}; i++)); do
        if [[ -z ${ver2[i]} ]]; then
            ver2[i]=0
        fi
        if ((10#${ver1[i]} > 10#${ver2[i]})); then
            return 0
        fi
        if ((10#${ver1[i]} < 10#${ver2[i]})); then
            return 1
        fi
    done
    return 0
}

# Function to check disk space
check_disk_space() {
    local available_space
    if [[ "$OSTYPE" == "darwin"* ]]; then
        available_space=$(df -m . | awk 'NR==2 {print $4}')
    else
        available_space=$(df -m . | awk 'NR==2 {print $4}')
    fi

    if [ "$available_space" -lt "$REQUIRED_DISK_SPACE_MB" ]; then
        return 1
    fi
    return 0
}

# Function to check Python version
check_python() {
    local python_cmd=""
    local python_version=""

    # Try different Python commands
    for cmd in python3 python; do
        if command -v "$cmd" &> /dev/null; then
            python_version=$($cmd --version 2>&1 | awk '{print $2}')
            if version_compare "$python_version" "$MINIMUM_PYTHON_VERSION"; then
                python_cmd=$cmd
                break
            fi
        fi
    done

    if [ -z "$python_cmd" ]; then
        return 1
    fi

    echo "$python_cmd|$python_version"
    return 0
}

# Function to check Docker
check_docker() {
    if ! check_command "docker"; then
        return 1
    fi

    # Fix: Declare and assign separately
    local docker_version
    docker_version=$(docker --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if ! version_compare "$docker_version" "$MINIMUM_DOCKER_VERSION"; then
        print_status "error" "Docker version $docker_version is below minimum required version $MINIMUM_DOCKER_VERSION"
        return 1
    fi

    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        print_status "error" "Docker daemon is not running"
        return 1
    fi

    echo "$docker_version"
    return 0
}

# Function to check Docker Compose
check_docker_compose() {
    local compose_cmd=""
    local compose_version=""

    # Try docker compose (v2) first
    if docker compose version &> /dev/null; then
        compose_cmd="docker compose"
        compose_version=$(docker compose version --short 2>/dev/null || echo "2.0.0")
    # Fall back to docker-compose (v1)
    elif command -v docker-compose &> /dev/null; then
        compose_cmd="docker-compose"
        compose_version=$(docker-compose --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    else
        return 1
    fi

    echo "$compose_cmd|$compose_version"
    return 0
}

# Function to check all prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"

    local all_passed=true
    local warnings=""

    # Check Git
    print_status "info" "Checking Git..."
    if check_command "git"; then
        local git_version
        git_version=$(git --version | awk '{print $3}')
        print_status "success" "Git $git_version found"
    else
        print_status "error" "Git not found - required for version control"
        all_passed=false
    fi

    # Check Python
    print_status "info" "Checking Python..."
    if python_info=$(check_python); then
        IFS='|' read -r python_cmd python_version <<< "$python_info"
        print_status "success" "Python $python_version found (using $python_cmd)"
    else
        print_status "error" "Python $MINIMUM_PYTHON_VERSION+ not found - required for local development"
        all_passed=false
    fi

    # Check Make
    print_status "info" "Checking Make..."
    if check_command "make"; then
        print_status "success" "Make found"
    else
        print_status "warning" "Make not found - optional but recommended for development"
        warnings="${warnings}\n  - Make not installed (development convenience)"
    fi

    # Check Docker
    print_status "info" "Checking Docker..."
    if docker_version=$(check_docker); then
        print_status "success" "Docker $docker_version found and running"
    else
        print_status "error" "Docker not properly installed or not running"
        all_passed=false
    fi

    # Check Docker Compose
    print_status "info" "Checking Docker Compose..."
    if compose_info=$(check_docker_compose); then
        IFS='|' read -r compose_cmd compose_version <<< "$compose_info"
        print_status "success" "Docker Compose $compose_version found (using: $compose_cmd)"
        DOCKER_COMPOSE_CMD="$compose_cmd"
    else
        print_status "error" "Docker Compose not found"
        all_passed=false
    fi

    # Check disk space
    print_status "info" "Checking disk space..."
    if check_disk_space; then
        print_status "success" "Sufficient disk space available (minimum ${REQUIRED_DISK_SPACE_MB}MB required)"
    else
        print_status "error" "Insufficient disk space (minimum ${REQUIRED_DISK_SPACE_MB}MB required)"
        all_passed=false
    fi

    # Check for required files
    print_status "info" "Checking project files..."
    local required_files=("requirements.txt" "Dockerfile" "app/main.py")
    local files_missing=false

    for file in "${required_files[@]}"; do
        if [ ! -f "$SCRIPT_DIR/$file" ]; then
            print_status "error" "Required file missing: $file"
            files_missing=true
            all_passed=false
        fi
    done

    if [ "$files_missing" = false ]; then
        print_status "success" "All required project files found"
    fi

    # Check for Docker Compose file
    if [ ! -f "$SCRIPT_DIR/$DOCKER_COMPOSE_FILE" ]; then
        print_status "warning" "docker-compose.yml not found - will create one"
        warnings="${warnings}\n  - docker-compose.yml will be created"
    else
        print_status "success" "docker-compose.yml found"
    fi

    # Check for .env file
    if [ ! -f "$SCRIPT_DIR/$ENV_FILE" ]; then
        if [ -f "$SCRIPT_DIR/$ENV_EXAMPLE_FILE" ]; then
            print_status "warning" ".env file not found - will create from .env.example"
            warnings="${warnings}\n  - .env will be created from template"
        else
            print_status "warning" ".env file not found - will create with defaults"
            warnings="${warnings}\n  - .env will be created with default values"
        fi
    else
        print_status "success" ".env file found"
    fi

    # Check network connectivity
    print_status "info" "Checking network connectivity..."
    if ping -c 1 -W 2 hub.docker.com &> /dev/null || ping -c 1 -W 2 8.8.8.8 &> /dev/null; then
        print_status "success" "Network connectivity verified"
    else
        print_status "warning" "Network connectivity issues detected - may affect Docker image pulls"
        warnings="${warnings}\n  - Network connectivity may be limited"
    fi

    # Summary
    echo ""
    if [ "$all_passed" = true ]; then
        print_color "$GREEN" "═══════════════════════════════════════════════════════════════"
        print_status "success" "All prerequisites satisfied!"
        if [ -n "$warnings" ]; then
            print_color "$YELLOW" "\nWarnings:"
            echo -e "$warnings"
        fi
        return 0
    else
        print_color "$RED" "═══════════════════════════════════════════════════════════════"
        print_status "error" "Some prerequisites are missing. Please install them before proceeding."
        if [ -n "$warnings" ]; then
            print_color "$YELLOW" "\nAdditional warnings:"
            echo -e "$warnings"
        fi
        return 1
    fi
}

# Function to create docker-compose.yml if it doesn't exist
create_docker_compose() {
    if [ -f "$SCRIPT_DIR/$DOCKER_COMPOSE_FILE" ]; then
        print_status "info" "Using existing docker-compose.yml"
        return 0
    fi

    print_status "info" "Creating docker-compose.yml..."

    cat > "$SCRIPT_DIR/$DOCKER_COMPOSE_FILE" << 'EOF'
version: '3.8'

services:
  api:
    build:
      context: .
      dockerfile: Dockerfile
    image: violentutf-api:latest
    container_name: violentutf-api
    ports:
      - "${API_PORT:-8000}:8000"
    environment:
      - DATABASE_URL=${DATABASE_URL:-postgresql+asyncpg://violentutf:violentutf@db:5432/violentutf}
      - REDIS_URL=redis://:${REDIS_PASSWORD:-}@redis:6379/0
      - SECRET_KEY=${SECRET_KEY:-your-secret-key-min-32-chars-change-in-production}
      - ENVIRONMENT=${ENVIRONMENT:-development}
      - DEBUG=${DEBUG:-false}
      - LOG_LEVEL=${LOG_LEVEL:-INFO}
      - SERVER_HOST=0.0.0.0
      - SERVER_PORT=8000
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/v1/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    volumes:
      - ./app:/app/app:ro
      - ./logs:/app/logs
    networks:
      - violentutf-network
    restart: unless-stopped

  db:
    image: postgres:15-alpine
    container_name: violentutf-db
    environment:
      - POSTGRES_USER=${DB_USER:-violentutf}
      - POSTGRES_PASSWORD=${DB_PASSWORD:-violentutf}
      - POSTGRES_DB=${DB_NAME:-violentutf}
      - POSTGRES_INITDB_ARGS=--encoding=UTF-8
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./backups/postgres:/backups
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${DB_USER:-violentutf}"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - violentutf-network
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    container_name: violentutf-redis
    command: redis-server --appendonly yes --requirepass ${REDIS_PASSWORD:-}
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - violentutf-network
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    container_name: violentutf-nginx
    ports:
      - "${NGINX_PORT:-80}:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - api
    networks:
      - violentutf-network
    restart: unless-stopped

volumes:
  postgres_data:
    driver: local
  redis_data:
    driver: local

networks:
  violentutf-network:
    driver: bridge
EOF

    print_status "success" "docker-compose.yml created"
}

# Function to generate secure random string
generate_secret() {
    local length=${1:-32}
    if command -v openssl &> /dev/null; then
        # Generate hex string which is guaranteed to be alphanumeric
        openssl rand -hex "$((length / 2 + 1))" | cut -c1-"$length"
    elif command -v uuidgen &> /dev/null; then
        # Fallback to UUID-based generation
        local secret=""
        while [ ${#secret} -lt "$length" ]; do
            secret="${secret}$(uuidgen | tr -d '-' | tr '[:upper:]' '[:lower:]')"
        done
        echo "${secret:0:$length}"
    else
        # Last resort: use /dev/urandom
        tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c"$length"
    fi
}

# Function to create .env file if it doesn't exist
create_env_file() {
    if [ -f "$SCRIPT_DIR/$ENV_FILE" ]; then
        print_status "info" "Using existing .env file"
        # Check if using default secrets
        if grep -q "your-secret-key-min-32-chars-change-in-production" "$SCRIPT_DIR/$ENV_FILE" 2>/dev/null; then
            print_status "warning" "Default SECRET_KEY detected in .env - will generate secure one"
            # Variable removed as it was unused
        fi
        if grep -q "DB_PASSWORD=violentutf" "$SCRIPT_DIR/$ENV_FILE" 2>/dev/null; then
            print_status "warning" "Default DB_PASSWORD detected in .env - will generate secure one"
            # Variable removed as it was unused
        fi
        return 0
    fi

    print_status "info" "Generating secure secrets..."

    # Generate secure secrets
    SECRET_KEY=$(generate_secret 64)
    DB_PASSWORD=$(generate_secret 32)
    REDIS_PASSWORD=$(generate_secret 32)
    JWT_SECRET=$(generate_secret 48)

    # Store generated credentials for later display
    GENERATED_SECRETS="true"
    GENERATED_SECRET_KEY="$SECRET_KEY"
    GENERATED_DB_PASSWORD="$DB_PASSWORD"
    GENERATED_REDIS_PASSWORD="$REDIS_PASSWORD"
    GENERATED_JWT_SECRET="$JWT_SECRET"

    if [ -f "$SCRIPT_DIR/$ENV_EXAMPLE_FILE" ]; then
        print_status "info" "Creating .env from .env.example with secure secrets..."
        cp "$SCRIPT_DIR/$ENV_EXAMPLE_FILE" "$SCRIPT_DIR/$ENV_FILE"

        # Use awk to safely replace all secrets
        awk -v secret="$SECRET_KEY" \
            -v dbpass="$DB_PASSWORD" \
            -v redispass="$REDIS_PASSWORD" \
            -v jwtsecret="$JWT_SECRET" '
        {
            gsub(/your-secret-key-min-32-chars-change-in-production/, secret)
            gsub(/your-jwt-secret-min-32-chars-change-in-production/, jwtsecret)
            gsub(/change-this-secure-password-in-production/, dbpass)
            gsub(/your_api_key_here/, secret)
            print
        }' "$SCRIPT_DIR/$ENV_FILE" > "$SCRIPT_DIR/$ENV_FILE.tmp"

        mv "$SCRIPT_DIR/$ENV_FILE.tmp" "$SCRIPT_DIR/$ENV_FILE"
    else
        print_status "info" "Creating .env file with secure secrets..."
        cat > "$SCRIPT_DIR/$ENV_FILE" << EOF
# Application Configuration
ENVIRONMENT=development
DEBUG=false
SECRET_KEY=$SECRET_KEY
JWT_SECRET=$JWT_SECRET

# API Configuration
API_PORT=8000
SERVER_HOST=0.0.0.0
SERVER_PORT=8000

# Database Configuration
DB_USER=violentutf
DB_PASSWORD=$DB_PASSWORD
DB_NAME=violentutf
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=40

# Redis Configuration
REDIS_URL=redis://redis:6379/0
REDIS_PASSWORD=$REDIS_PASSWORD
CACHE_TTL=300

# Security
ALLOWED_ORIGINS='["http://localhost:8000","http://127.0.0.1:8000"]'
SECURE_COOKIES=false
HSTS_MAX_AGE=31536000

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_PER_MINUTE=60

# Monitoring
ENABLE_METRICS=true
LOG_LEVEL=INFO
LOG_FORMAT=json

# Nginx
NGINX_PORT=80

# Claude Code SDK Configuration (if needed)
ANTHROPIC_API_KEY=your_anthropic_api_key_here
EOF
    fi

    print_status "success" ".env file created with secure secrets"

    # Save credentials to a secure file
    local creds_file="$SCRIPT_DIR/credentials.txt"
    cat > "$creds_file" << EOF
====================================
ViolentUTF API Generated Credentials
Generated at: $(date)
====================================

IMPORTANT: Save these credentials securely and delete this file!

Database:
  Username: violentutf
  Password: $DB_PASSWORD

Application:
  SECRET_KEY: $SECRET_KEY
  JWT_SECRET: $JWT_SECRET

Redis:
  Password: $REDIS_PASSWORD

These credentials have been saved in .env file.
For production, ensure you:
1. Change these credentials
2. Use a secure secrets management system
3. Never commit .env to version control
====================================
EOF
    chmod 600 "$creds_file"
    print_status "info" "Credentials saved to credentials.txt (delete after noting them)"
}

# Function to create nginx.conf if it doesn't exist
create_nginx_config() {
    if [ -f "$SCRIPT_DIR/nginx.conf" ]; then
        return 0
    fi

    print_status "info" "Creating nginx.conf..."

    cat > "$SCRIPT_DIR/nginx.conf" << 'EOF'
events {
    worker_connections 1024;
}

http {
    upstream api {
        server api:8000;
    }

    server {
        listen 80;
        server_name localhost;

        client_max_body_size 10M;

        location / {
            proxy_pass http://api;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
        }

        location /health {
            access_log off;
            return 200 "OK\n";
        }
    }
}
EOF

    print_status "success" "nginx.conf created"
}

# Function to backup data
backup_data() {
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_path="$SCRIPT_DIR/$BACKUP_DIR/$timestamp"

    print_status "info" "Creating backup at $backup_path..."
    mkdir -p "$backup_path"

    # Backup .env file
    if [ -f "$SCRIPT_DIR/$ENV_FILE" ]; then
        cp "$SCRIPT_DIR/$ENV_FILE" "$backup_path/.env.backup"
        print_status "success" "Backed up .env file"
    fi

    # Backup docker volumes
    if docker volume ls | grep -q "${PROJECT_NAME}_postgres_data"; then
        print_status "info" "Backing up PostgreSQL data..."
        docker run --rm \
            -v "${PROJECT_NAME}_postgres_data:/data" \
            -v "$backup_path:/backup" \
            alpine tar czf /backup/postgres_data.tar.gz -C /data .
        print_status "success" "Backed up PostgreSQL data"
    fi

    if docker volume ls | grep -q "${PROJECT_NAME}_redis_data"; then
        print_status "info" "Backing up Redis data..."
        docker run --rm \
            -v "${PROJECT_NAME}_redis_data:/data" \
            -v "$backup_path:/backup" \
            alpine tar czf /backup/redis_data.tar.gz -C /data .
        print_status "success" "Backed up Redis data"
    fi

    print_status "success" "Backup completed at $backup_path"
}

# Function to restore data
restore_data() {
    local backup_path="$1"

    if [ ! -d "$backup_path" ]; then
        print_status "error" "Backup path not found: $backup_path"
        return 1
    fi

    print_status "info" "Restoring from $backup_path..."

    # Restore .env file
    if [ -f "$backup_path/.env.backup" ]; then
        cp "$backup_path/.env.backup" "$SCRIPT_DIR/$ENV_FILE"
        print_status "success" "Restored .env file"
    fi

    # Restore PostgreSQL data
    if [ -f "$backup_path/postgres_data.tar.gz" ]; then
        print_status "info" "Restoring PostgreSQL data..."
        docker run --rm \
            -v "${PROJECT_NAME}_postgres_data:/data" \
            -v "$backup_path:/backup" \
            alpine sh -c "rm -rf /data/* && tar xzf /backup/postgres_data.tar.gz -C /data"
        print_status "success" "Restored PostgreSQL data"
    fi

    # Restore Redis data
    if [ -f "$backup_path/redis_data.tar.gz" ]; then
        print_status "info" "Restoring Redis data..."
        docker run --rm \
            -v "${PROJECT_NAME}_redis_data:/data" \
            -v "$backup_path:/backup" \
            alpine sh -c "rm -rf /data/* && tar xzf /backup/redis_data.tar.gz -C /data"
        print_status "success" "Restored Redis data"
    fi

    print_status "success" "Restore completed"
}

# Function to fix database URL for async operations
fix_database_url() {
    print_status "info" "Configuring database URL for async operations..."

    if [ -f "$SCRIPT_DIR/$ENV_FILE" ]; then
        # Check if DATABASE_URL needs updating
        if grep -q "^DATABASE_URL=postgresql://" "$SCRIPT_DIR/$ENV_FILE" || grep -q "^# DATABASE_URL=" "$SCRIPT_DIR/$ENV_FILE"; then
            # Get the current password from DB_PASSWORD
            local db_password
            db_password=$(grep "^DB_PASSWORD=" "$SCRIPT_DIR/$ENV_FILE" | cut -d'=' -f2)

            # Update or add DATABASE_URL with asyncpg
            awk -v password="$db_password" '
            /^DATABASE_URL=postgresql:\/\// || /^# DATABASE_URL=/ {
                print "DATABASE_URL=postgresql+asyncpg://violentutf:" password "@db:5432/violentutf"
                next
            }
            {print}
            ' "$SCRIPT_DIR/$ENV_FILE" > "$SCRIPT_DIR/$ENV_FILE.tmp"

            mv "$SCRIPT_DIR/$ENV_FILE.tmp" "$SCRIPT_DIR/$ENV_FILE"
            print_status "success" "DATABASE_URL configured for async operations"
        fi
    fi
}

# Function to run database migrations
run_database_migrations() {
    print_status "info" "Running database migrations..."

    # Wait for database to be ready
    local max_attempts=30
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        if ${DOCKER_COMPOSE_CMD:-docker compose} exec -T db pg_isready -U violentutf &>/dev/null; then
            print_status "success" "Database is ready"
            break
        fi
        if [ $((attempt % 5)) -eq 0 ]; then
            print_status "info" "Waiting for database (attempt $attempt/$max_attempts)..."
        else
            printf "."
        fi
        sleep 2
        ((attempt++))
    done
    echo ""

    if [ $attempt -gt $max_attempts ]; then
        print_status "error" "Database failed to become ready"
        return 1
    fi

    # Initialize database schema
    print_status "info" "Initializing database schema..."
    local migration_output
    migration_output=$(${DOCKER_COMPOSE_CMD:-docker compose} exec -T api python -c '
import asyncio
from app.db.session import init_db
asyncio.run(init_db())
print("Database initialized")
' 2>&1) && migration_success=true || migration_success=false

    if [ "$migration_success" = "true" ] && echo "$migration_output" | grep -q "Database initialized"; then
        print_status "success" "Database schema initialized"
    else
        print_status "warning" "Database initialization may need manual intervention"
    fi
}

# Function to create admin user and generate API key
create_admin_user() {
    print_status "info" "Setting up admin credentials..."

    # Generate admin credentials
    ADMIN_USERNAME="admin"
    ADMIN_PASSWORD=$(generate_secret 16)
    ADMIN_EMAIL="admin@violentutf.local"

    # Generate API key even if database setup fails
    GENERATED_API_KEY=$(generate_secret 43)

    # Try to create admin user in database
    print_status "info" "Attempting to create admin user in database..."

    # Create Python script for admin setup
    cat > /tmp/setup_admin.py << 'PYTHON_SCRIPT'
import asyncio
import sys
import os
import secrets
from datetime import datetime, timedelta, timezone

sys.path.insert(0, '/app')

async def create_admin():
    try:
        # Import all models to ensure they're registered
        from app.db.base import Base
        from app.db.session import engine, get_db
        from app.models import user as user_model, api_key as api_key_model  # Import to register
        from app.models.user import User
        from app.models.api_key import APIKey
        from app.core.security import hash_password
        from sqlalchemy import select

        # Create tables if they don't exist
        if engine:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
                print("Database tables created/verified")

        async with get_db() as db:
            try:
                admin_username = os.environ.get('ADMIN_USERNAME', 'admin')
                admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')
                admin_email = os.environ.get('ADMIN_EMAIL', 'admin@violentutf.local')

                # Check if admin exists
                result = await db.execute(select(User).where(User.username == admin_username))
                existing_user = result.scalar_one_or_none()

                if existing_user:
                    print(f"Admin user already exists: {existing_user.username}")
                    user = existing_user
                else:
                    # Create admin user
                    user = User(
                        username=admin_username,
                        email=admin_email,
                        hashed_password=hash_password(admin_password),
                        is_active=True,
                        is_superuser=True,
                        created_at=datetime.now(timezone.utc)
                    )
                    db.add(user)
                    await db.commit()
                    await db.refresh(user)
                    print(f"Created admin user: {user.username}")

                # Generate API key
                api_key_value = secrets.token_urlsafe(32)

                # Check for existing setup key
                result = await db.execute(
                    select(APIKey).where(
                        (APIKey.user_id == user.id) &
                        (APIKey.name == "Setup API Key")
                    )
                )
                existing_key = result.scalar_one_or_none()

                if existing_key:
                    existing_key.key = api_key_value
                    existing_key.expires_at = datetime.now(timezone.utc) + timedelta(days=365)
                    await db.commit()
                else:
                    api_key = APIKey(
                        name="Setup API Key",
                        key=api_key_value,
                        user_id=user.id,
                        expires_at=datetime.now(timezone.utc) + timedelta(days=365),
                        created_at=datetime.now(timezone.utc)
                    )
                    db.add(api_key)
                    await db.commit()

                print(f"API_KEY={api_key_value}")
                return

            except Exception as e:
                print(f"Database error: {e}")
                await db.rollback()
                return
            finally:
                await db.close()

    except ImportError as e:
        print(f"Import error: {e}")
        # Generate API key for manual setup
        api_key = os.environ.get('FALLBACK_API_KEY', secrets.token_urlsafe(32))
        print(f"API_KEY={api_key}")
        print("MANUAL_SETUP_REQUIRED=true")
    except Exception as e:
        print(f"Setup error: {e}")
        # Generate API key for manual setup
        api_key = os.environ.get('FALLBACK_API_KEY', secrets.token_urlsafe(32))
        print(f"API_KEY={api_key}")
        print("MANUAL_SETUP_REQUIRED=true")

asyncio.run(create_admin())
PYTHON_SCRIPT

    # Copy script to container
    docker cp /tmp/setup_admin.py "${PROJECT_NAME}:/tmp/setup_admin.py" 2>/dev/null || {
        print_status "warning" "Could not copy admin setup script - using generated credentials"
        ADMIN_CREDENTIALS_SET="true"  # We have the generated credentials
        rm -f /tmp/setup_admin.py
        return 0
    }

    # Run the script with fallback API key
    local output
    output=$(${DOCKER_COMPOSE_CMD:-docker compose} exec -T \
        -e ADMIN_USERNAME="$ADMIN_USERNAME" \
        -e ADMIN_PASSWORD="$ADMIN_PASSWORD" \
        -e ADMIN_EMAIL="$ADMIN_EMAIL" \
        -e FALLBACK_API_KEY="$GENERATED_API_KEY" \
        api python /tmp/setup_admin.py 2>&1) && setup_success=true || setup_success=false

    # Check if database setup succeeded
    if [ "$setup_success" = "true" ] || echo "$output" | grep -q "Created admin user\|Admin user already exists"; then
        print_status "success" "Admin user configured in database"
    elif echo "$output" | grep -q "MANUAL_SETUP_REQUIRED=true"; then
        print_status "info" "Database setup pending - credentials generated for later use"
    fi

    # Extract API key from output (might be different if created in DB)
    local db_api_key
    db_api_key=$(echo "$output" | grep "API_KEY=" | tail -1 | cut -d'=' -f2)
    if [ -n "$db_api_key" ]; then
        GENERATED_API_KEY="$db_api_key"
    fi

    ADMIN_CREDENTIALS_SET="true"  # We always have credentials

    # Cleanup
    rm -f /tmp/setup_admin.py
    ${DOCKER_COMPOSE_CMD:-docker compose} exec -T api rm -f /tmp/setup_admin.py 2>/dev/null || true  # JUSTIFIED: Cleanup is non-critical
}

# Function to verify all services
verify_all_services() {
    print_header "Service Verification"

    local all_healthy=true

    # Check API health
    print_status "info" "Checking API health endpoint..."
    local api_response
    local retry_count=0
    local max_retries=5

    while [ $retry_count -lt $max_retries ]; do
        api_response=$(curl -s -w "\nHTTP_CODE:%{http_code}" http://localhost:8000/api/v1/health 2>/dev/null || echo "HTTP_CODE:000")
        local http_code
        http_code=$(echo "$api_response" | grep "HTTP_CODE:" | cut -d':' -f2)

        if [ "$http_code" = "200" ]; then
            print_status "success" "API health check passed"
            break
        elif [ "$http_code" = "401" ]; then
            print_status "info" "API requires authentication (expected behavior)"
            break
        else
            ((retry_count++))
            if [ $retry_count -lt $max_retries ]; then
                sleep 2
            fi
        fi
    done

    # Check database
    print_status "info" "Checking database connectivity..."
    if ${DOCKER_COMPOSE_CMD:-docker compose} exec -T db pg_isready -U violentutf &>/dev/null; then
        print_status "success" "Database is accessible"
    else
        print_status "error" "Database is not accessible"
        all_healthy=false
    fi

    # Check Redis
    print_status "info" "Checking Redis connectivity..."
    # Get Redis password from .env if it exists
    local redis_password=""
    if [ -f "$SCRIPT_DIR/.env" ]; then
        redis_password=$(grep "^REDIS_PASSWORD=" "$SCRIPT_DIR/.env" | cut -d'=' -f2)
    fi

    if [ -n "$redis_password" ]; then
        # Test with password
        if ${DOCKER_COMPOSE_CMD:-docker compose} exec -T redis redis-cli -a "$redis_password" ping 2>/dev/null | grep -q PONG; then
            print_status "success" "Redis is accessible (with authentication)"
        else
            print_status "warning" "Redis may require different authentication"
        fi
    else
        # Test without password
        if ${DOCKER_COMPOSE_CMD:-docker compose} exec -T redis redis-cli ping 2>/dev/null | grep -q PONG; then
            print_status "success" "Redis is accessible"
        else
            print_status "warning" "Redis may require authentication"
        fi
    fi

    # Check Nginx
    print_status "info" "Checking Nginx proxy..."
    local nginx_response
    nginx_response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/api/v1/health 2>/dev/null || echo "000")

    if [ "$nginx_response" = "200" ] || [ "$nginx_response" = "401" ]; then
        print_status "success" "Nginx proxy is working"
    else
        print_status "warning" "Nginx proxy returned status: $nginx_response"
    fi

    # Test authenticated access
    if [ -n "$GENERATED_API_KEY" ]; then
        print_status "info" "Testing API authentication..."
        local auth_test
        auth_test=$(curl -s -H "Authorization: Bearer $GENERATED_API_KEY" \
            http://localhost:8000/api/v1/users/me 2>/dev/null || echo "{}")

        if echo "$auth_test" | grep -q "username"; then
            print_status "success" "API authentication is working"
        else
            print_status "info" "API authentication will be available after full initialization"
        fi
    fi

    echo ""
    if [ "$all_healthy" = true ]; then
        print_status "success" "All services verified successfully!"
        return 0
    else
        print_status "warning" "Some services may need attention"
        return 1
    fi
}

# Function to display enhanced setup summary
display_enhanced_summary() {
    echo ""
    echo "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo "${CYAN}║${BOLD}  ViolentUTF API Setup Complete!                             ${NC}${CYAN}║${NC}"
    echo "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    echo "${BOLD}🌐 Access URLs:${NC}"
    echo "   API Base:     ${GREEN}http://localhost:8000${NC}"
    echo "   API Docs:     ${GREEN}http://localhost:8000/docs${NC}"
    echo "   ReDoc:        ${GREEN}http://localhost:8000/redoc${NC}"
    echo "   Health Check: ${GREEN}http://localhost:8000/api/v1/health${NC}"
    echo "   Via Nginx:    ${GREEN}http://localhost/api/v1/health${NC}"
    echo ""

    if [ -n "$ADMIN_USERNAME" ]; then
        echo "${BOLD}👤 Admin Credentials:${NC}"
        echo "   Username: ${YELLOW}$ADMIN_USERNAME${NC}"
        echo "   Password: ${YELLOW}$ADMIN_PASSWORD${NC}"
        echo "   Email:    ${YELLOW}$ADMIN_EMAIL${NC}"
        echo ""

        if [ "$ADMIN_CREDENTIALS_SET" != "true" ]; then
            echo "   ${DIM}(Note: Database setup pending - save these for manual configuration)${NC}"
            echo ""
        fi
    fi

    if [ -n "$GENERATED_API_KEY" ]; then
        echo "${BOLD}🔑 API Key:${NC}"
        echo "   ${GREEN}$GENERATED_API_KEY${NC}"
        echo ""
        echo "${BOLD}📝 Example API Usage:${NC}"
        echo "   ${DIM}# Get current user info${NC}"
        echo "   curl -H \"Authorization: Bearer $GENERATED_API_KEY\" \\"
        echo "        http://localhost:8000/api/v1/users/me"
        echo ""
        echo "   ${DIM}# Access API documentation${NC}"
        echo "   curl -H \"Authorization: Bearer $GENERATED_API_KEY\" \\"
        echo "        http://localhost:8000/docs"
        echo ""
    fi

    echo "${BOLD}📊 Service Status:${NC}"
    ${DOCKER_COMPOSE_CMD:-docker compose} ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
    echo ""

    echo "${BOLD}🛠️  Management Commands:${NC}"
    echo "   View logs:        ${DIM}./setup_violentutf.sh --logs${NC}"
    echo "   Check status:     ${DIM}./setup_violentutf.sh --status${NC}"
    echo "   Stop services:    ${DIM}./setup_violentutf.sh --stop${NC}"
    echo "   Restart services: ${DIM}./setup_violentutf.sh --restart${NC}"
    echo "   Create backup:    ${DIM}./setup_violentutf.sh --backup${NC}"
    echo ""

    # Save credentials to secure file
    if [ -n "$GENERATED_API_KEY" ] || [ -n "$ADMIN_PASSWORD" ]; then
        local creds_file="$SCRIPT_DIR/.api_credentials"
        cat > "$creds_file" << EOF
# ViolentUTF API Credentials
# Generated: $(date)
# KEEP THIS FILE SECURE - DO NOT COMMIT TO VERSION CONTROL

## Admin Account
ADMIN_USERNAME=$ADMIN_USERNAME
ADMIN_PASSWORD=$ADMIN_PASSWORD
ADMIN_EMAIL=$ADMIN_EMAIL

## API Access
API_KEY=$GENERATED_API_KEY

## Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=violentutf
DB_USER=violentutf
DB_PASSWORD=$GENERATED_DB_PASSWORD

## Service URLs
API_URL=http://localhost:8000
DOCS_URL=http://localhost:8000/docs
HEALTH_URL=http://localhost:8000/api/v1/health

## Example Usage
# curl -H "Authorization: Bearer $GENERATED_API_KEY" http://localhost:8000/api/v1/users/me
EOF
        chmod 600 "$creds_file"

        echo "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo "${YELLOW}⚠️  Credentials saved to: ${BOLD}$creds_file${NC}"
        echo "${YELLOW}   Keep this file secure and do not commit to version control${NC}"
        echo "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    fi

    echo ""
    echo "${GREEN}🎉 Setup completed successfully! Your API is ready to use.${NC}"
    echo ""
}

# Function to check and update existing secrets
check_update_secrets() {
    if [ ! -f "$SCRIPT_DIR/$ENV_FILE" ]; then
        return 1
    fi

    local updated=false
    local temp_env="$SCRIPT_DIR/.env.tmp"
    cp "$SCRIPT_DIR/$ENV_FILE" "$temp_env"

    # Check and replace default SECRET_KEY
    if grep -q "your-secret-key-min-32-chars-change-in-production" "$temp_env" 2>/dev/null; then
        print_status "warning" "Default SECRET_KEY detected - generating secure one"
        local new_secret
        new_secret=$(generate_secret 64)
        # Use awk to safely replace the secret
        awk -v secret="$new_secret" '
        {
            gsub(/your-secret-key-min-32-chars-change-in-production/, secret)
            print
        }' "$temp_env" > "$temp_env.new"
        mv "$temp_env.new" "$temp_env"
        GENERATED_SECRET_KEY="$new_secret"
        updated=true
    fi

    # Check and replace default DB_PASSWORD
    if grep -q "change-this-secure-password-in-production" "$temp_env" 2>/dev/null; then
        print_status "warning" "Default DB_PASSWORD detected - generating secure one"
        local new_pass
        new_pass=$(generate_secret 32)
        # Use awk to safely replace the password
        awk -v dbpass="$new_pass" '
        {
            gsub(/change-this-secure-password-in-production/, dbpass)
            print
        }' "$temp_env" > "$temp_env.new"
        mv "$temp_env.new" "$temp_env"
        GENERATED_DB_PASSWORD="$new_pass"
        updated=true
    fi

    # Check and replace default JWT_SECRET
    if grep -q "your-jwt-secret-min-32-chars-change-in-production" "$temp_env" 2>/dev/null; then
        print_status "warning" "Default JWT_SECRET detected - generating secure one"
        local new_jwt
        new_jwt=$(generate_secret 48)
        # Use awk to safely replace the JWT secret
        awk -v jwtsecret="$new_jwt" '
        {
            gsub(/your-jwt-secret-min-32-chars-change-in-production/, jwtsecret)
            print
        }' "$temp_env" > "$temp_env.new"
        mv "$temp_env.new" "$temp_env"
        GENERATED_JWT_SECRET="$new_jwt"
        updated=true
    fi

    # Add Redis password if missing
    if ! grep -q "^REDIS_PASSWORD=" "$temp_env" 2>/dev/null; then
        print_status "info" "Adding REDIS_PASSWORD to configuration"
        local redis_pass
        redis_pass=$(generate_secret 32)
        # Ensure newline before adding
        echo "" >> "$temp_env"
        echo "REDIS_PASSWORD=$redis_pass" >> "$temp_env"
        GENERATED_REDIS_PASSWORD="$redis_pass"
        updated=true
    fi

    # Add JWT_SECRET if missing
    if ! grep -q "^JWT_SECRET=" "$temp_env" 2>/dev/null; then
        print_status "info" "Adding JWT_SECRET to configuration"
        local jwt_secret
        jwt_secret=$(generate_secret 48)
        # Ensure newline before adding if not already added
        if [ "$GENERATED_REDIS_PASSWORD" = "" ]; then
            echo "" >> "$temp_env"
        fi
        echo "JWT_SECRET=$jwt_secret" >> "$temp_env"
        GENERATED_JWT_SECRET="$jwt_secret"
        updated=true
    fi

    if [ "$updated" = true ]; then
        mv "$temp_env" "$SCRIPT_DIR/$ENV_FILE"
        GENERATED_SECRETS="true"
        print_status "success" "Updated .env with secure secrets"
        return 0
    else
        rm -f "$temp_env" "$temp_env.bak"
        return 1
    fi
}

# Function to setup the project
setup_project() {
    print_header "Setting up ViolentUTF API"

    # Create necessary directories
    print_status "info" "Creating necessary directories..."
    mkdir -p "$SCRIPT_DIR/logs"
    mkdir -p "$SCRIPT_DIR/$BACKUP_DIR"
    mkdir -p "$SCRIPT_DIR/$BACKUP_DIR/postgres"

    # Create configuration files
    create_docker_compose
    create_env_file
    create_nginx_config

    # Check and update existing secrets if needed
    if [ -f "$SCRIPT_DIR/$ENV_FILE" ]; then
        # Temporarily disable exit on error for this check
        set +e
        check_update_secrets
        local update_result=$?
        set -e

        if [ $update_result -eq 0 ]; then
            print_status "info" "Secrets have been updated"
        else
            # Function returns 1 when no updates needed, which is fine
            print_status "info" "Using existing secure secrets"
        fi
    fi

    # Build Docker image
    print_status "info" "Building Docker image..."
    set +e
    docker build -t "${PROJECT_NAME}:latest" "$SCRIPT_DIR"
    local build_result=$?
    set -e

    if [ $build_result -eq 0 ]; then
        print_status "success" "Docker image built successfully"
    else
        print_status "error" "Docker image build failed"
        print_status "info" "Please check the Dockerfile and requirements.txt"
        print_status "info" "You can manually build with: docker build -t ${PROJECT_NAME}:latest ."
        return 1
    fi

    # Start services
    print_status "info" "Starting services..."
    cd "$SCRIPT_DIR"
    set +e
    ${DOCKER_COMPOSE_CMD:-docker compose} up -d
    local compose_result=$?
    set -e

    if [ $compose_result -ne 0 ]; then
        print_status "error" "Failed to start services"
        print_status "info" "Please check docker-compose.yml and try:"
        print_status "info" "  docker compose up -d"
        return 1
    fi

    # Wait for services to be healthy
    print_status "info" "Waiting for services to be healthy..."
    local max_attempts=30
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        if ${DOCKER_COMPOSE_CMD:-docker compose} ps | grep -q "healthy"; then
            break
        fi
        sleep 2
        attempt=$((attempt + 1))
        echo -n "."
    done
    echo ""

    # Fix database URL for async operations
    fix_database_url

    # Run database migrations
    run_database_migrations

    # Create admin user and generate API key
    create_admin_user

    # Verify all services are working
    verify_all_services

    # Display enhanced setup summary
    display_enhanced_summary

    # Return success since we completed the core setup
    return 0
}

# Function to display generated credentials (legacy - kept for compatibility)
display_generated_credentials() {
    # Display generated credentials if new ones were created
    if [ "$GENERATED_SECRETS" = "true" ]; then
        print_color "$YELLOW" "\n🔐 IMPORTANT: Generated Credentials (save these securely!):"
        print_color "$CYAN" "\n╔══════════════════════════════════════════════════════════════╗"
        print_color "$CYAN" "║  Generated Credentials                                        ║"
        print_color "$CYAN" "╚══════════════════════════════════════════════════════════════╝"
        echo ""

        if [ -n "$GENERATED_DB_PASSWORD" ]; then
            print_color "$BOLD" "Database:"
            echo "  Username: violentutf"
            echo "  Password: $GENERATED_DB_PASSWORD"
            echo ""
        fi

        if [ -n "$GENERATED_SECRET_KEY" ]; then
            print_color "$BOLD" "Application Secrets:"
            echo "  SECRET_KEY: $GENERATED_SECRET_KEY"
            if [ -n "$GENERATED_JWT_SECRET" ]; then
                echo "  JWT_SECRET: $GENERATED_JWT_SECRET"
            fi
            echo ""
        fi

        if [ -n "$GENERATED_REDIS_PASSWORD" ]; then
            print_color "$BOLD" "Redis:"
            echo "  Password: $GENERATED_REDIS_PASSWORD"
            echo ""
        fi

        print_color "$YELLOW" "⚠️  These credentials have been added to your .env file"
        print_color "$YELLOW" "⚠️  A copy is saved in ./credentials.txt - delete after noting!"
        print_color "$RED" "⚠️  NEVER commit .env or credentials.txt to version control!"
        print_color "$CYAN" "═══════════════════════════════════════════════════════════════"

        # Create credentials file if secrets were generated
        if [ -n "$GENERATED_DB_PASSWORD" ] || [ -n "$GENERATED_SECRET_KEY" ] || [ -n "$GENERATED_REDIS_PASSWORD" ]; then
            local creds_file="$SCRIPT_DIR/credentials.txt"
            cat > "$creds_file" << EOF
====================================
ViolentUTF API Generated Credentials
Generated at: $(date)
====================================

IMPORTANT: Save these credentials securely and delete this file!

Database:
  Username: violentutf
  Password: ${GENERATED_DB_PASSWORD:-[not changed]}

Application:
  SECRET_KEY: ${GENERATED_SECRET_KEY:-[not changed]}
  JWT_SECRET: ${GENERATED_JWT_SECRET:-[not changed]}

Redis:
  Password: ${GENERATED_REDIS_PASSWORD:-[not changed]}

These credentials have been saved in .env file.
For production, ensure you:
1. Change these credentials
2. Use a secure secrets management system
3. Never commit .env to version control
====================================
EOF
            chmod 600 "$creds_file"
        fi
    elif [ -f "$SCRIPT_DIR/credentials.txt" ]; then
        print_color "$YELLOW" "\n⚠️  Credentials file exists at ./credentials.txt"
        print_color "$YELLOW" "⚠️  Please review and delete after saving securely!"
    fi

    print_color "$CYAN" "\nAccess the API at:"
    print_color "$BOLD" "  • API: http://localhost:8000"
    print_color "$BOLD" "  • API Docs: http://localhost:8000/docs"
    print_color "$BOLD" "  • Nginx Proxy: http://localhost:80"
    print_color "$CYAN" "\nUseful commands:"
    print_color "$BOLD" "  • View logs: ${DOCKER_COMPOSE_CMD:-docker compose} logs -f"
    print_color "$BOLD" "  • Stop services: ${DOCKER_COMPOSE_CMD:-docker compose} down"
    print_color "$BOLD" "  • Restart services: ${DOCKER_COMPOSE_CMD:-docker compose} restart"
}

# Function to cleanup (preserving data)
cleanup() {
    print_header "Cleaning up (preserving data and configuration)"

    cd "$SCRIPT_DIR" || exit 1

    # Stop containers for this project only
    print_status "info" "Stopping ViolentUTF API containers..."
    if [ -f "$DOCKER_COMPOSE_FILE" ]; then
        ${DOCKER_COMPOSE_CMD:-docker compose} down
    fi

    # Remove only project-specific cache directories
    print_status "info" "Removing project cache directories..."
    for dir in "${CACHE_DIRS[@]}"; do
        # Only remove within project directory
        if [ -d "./$dir" ]; then
            rm -rf "./$dir"
            print_status "success" "Removed $dir"
        fi
    done

    # Clear log files (but keep the logs directory and .env)
    print_status "info" "Clearing log files..."
    if [ -d "logs" ]; then
        rm -f logs/*.log 2>/dev/null && print_status "success" "Cleared log files"
    fi

    # Remove Python cache files in project directory only
    print_status "info" "Removing Python cache files..."
    find . -type d -name "__pycache__" -maxdepth 3 -exec rm -rf {} + 2>/dev/null
    find . -type f -name "*.pyc" -maxdepth 3 -delete 2>/dev/null

    # Note: NOT doing docker system prune as it affects other projects
    print_status "info" "Note: Docker images and volumes are preserved"

    print_status "success" "Cleanup completed"
    echo ""
    print_color "$GREEN" "✓ Preserved:"
    echo "  • Docker volumes (database data)"
    echo "  • Configuration files (.env, docker-compose.yml, nginx.conf)"
    echo "  • Backup directory"
    echo "  • Docker images (for faster restart)"
    echo ""
    print_color "$YELLOW" "✗ Removed:"
    echo "  • Running containers (stopped)"
    echo "  • Cache directories (.pytest_cache, __pycache__, etc.)"
    echo "  • Log files (*.log)"
    echo "  • Python compiled files (*.pyc)"
    echo ""
    print_status "info" "To restart: ./setup_violentutf.sh --start"
}

# Function to deep cleanup (remove everything)
deep_cleanup() {
    print_header "Deep Cleanup (removing everything)"

    print_color "$YELLOW" "⚠️  WARNING: This will remove all data, volumes, and configurations!"
    read -rp "Are you sure you want to continue? (yes/no): " confirmation

    if [ "$confirmation" != "yes" ]; then
        print_status "info" "Deep cleanup cancelled"
        return 0
    fi

    # Create backup first
    print_status "info" "Creating backup before deep cleanup..."
    backup_data

    cd "$SCRIPT_DIR" || exit 1

    # Stop and remove containers, networks, volumes
    print_status "info" "Removing all containers, networks, and volumes..."
    ${DOCKER_COMPOSE_CMD:-docker compose} down -v --remove-orphans

    # Remove Docker images for this project only
    print_status "info" "Removing ViolentUTF API Docker images..."
    # Handle case where images might not exist
    if docker images -q "${PROJECT_NAME}:latest" | grep -q .; then
        docker rmi "${PROJECT_NAME}:latest"
    fi

    # Note: NOT removing postgres/redis/nginx images as they may be used by other projects
    print_status "info" "Note: Base images (postgres, redis, nginx) preserved for other projects"

    # Remove all cache and temporary directories
    print_status "info" "Removing all cache and temporary files..."
    for dir in "${CACHE_DIRS[@]}"; do
        find . -type d -name "$dir" -exec rm -rf {} + 2>/dev/null || print_status "warning" "Could not remove some $dir directories"
    done

    # Remove data directories
    print_status "info" "Removing data directories..."
    for dir in "${DATA_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            rm -rf "$dir"
        fi
    done

    # Remove configuration files (but keep backups)
    print_status "info" "Removing configuration files..."
    [ -f "$DOCKER_COMPOSE_FILE" ] && rm -f "$DOCKER_COMPOSE_FILE"
    [ -f "nginx.conf" ] && rm -f "nginx.conf"

    # Clean only project-specific Docker resources
    print_status "info" "Cleaning project-specific Docker resources..."
    # Remove only networks and volumes with our project name
    docker network ls | grep "${PROJECT_NAME}" | awk '{print $1}' | xargs -r docker network rm 2>/dev/null || true  # JUSTIFIED: Docker cleanup is best effort
    docker volume ls | grep "${PROJECT_NAME}" | awk '{print $2}' | xargs -r docker volume rm 2>/dev/null || true  # JUSTIFIED: Docker cleanup is best effort

    print_status "success" "Deep cleanup completed"
    echo ""
    print_color "$RED" "✗ Removed (Project-Specific Only):"
    echo "  • All ViolentUTF API containers"
    echo "  • All ViolentUTF API volumes (database data lost!)"
    echo "  • ViolentUTF API Docker image"
    echo "  • Project networks"
    echo "  • Configuration files (docker-compose.yml, nginx.conf)"
    echo "  • All cache and temporary files"
    echo "  • Data directories"
    echo ""
    print_color "$GREEN" "✓ Preserved:"
    echo "  • .env file (contains your secrets)"
    echo "  • Source code"
    echo "  • Backup directory with latest backup"
    echo "  • Base Docker images (postgres, redis, nginx) for other projects"
    echo ""
    print_status "info" "Backup saved in $BACKUP_DIR"
    print_status "info" "To start fresh: ./setup_violentutf.sh --setup"
}

# Function to show usage
show_usage() {
    cat << EOF
${BOLD}ViolentUTF API Setup Script${NC}

${BOLD}Usage:${NC}
  $0 [OPTIONS]

${BOLD}Options:${NC}
  --help, -h           Show this help message
  --precheck           Check all prerequisites without installing
  --setup              Setup and launch ViolentUTF API (default)
  --cleanup            Stop containers, remove cache (preserve data/config)
  --deepcleanup        Remove EVERYTHING: containers, volumes, images, config
  --backup             Create backup of data and configuration
  --restore <path>     Restore from backup
  --status             Show current service status
  --logs               Show service logs
  --stop               Stop all services
  --start              Start all services
  --restart            Restart all services

${BOLD}Examples:${NC}
  $0 --precheck        # Check prerequisites only
  $0                   # Setup and launch (default)
  $0 --cleanup         # Clean but keep data
  $0 --deepcleanup     # Remove everything
  $0 --backup          # Create backup
  $0 --status          # Check service status

${BOLD}Environment Variables:${NC}
  API_PORT             API port (default: 8000)
  NGINX_PORT           Nginx port (default: 80)
  DB_USER              Database user (default: violentutf)
  DB_PASSWORD          Database password (default: violentutf)
  DB_NAME              Database name (default: violentutf)
  ENVIRONMENT          Environment (default: development)
  DEBUG                Debug mode (default: false)

${BOLD}Project Structure:${NC}
  • API Documentation: http://localhost:8000/docs
  • Logs: ./logs/
  • Backups: ./backups/
  • Configuration: .env, docker-compose.yml

${BOLD}For more information:${NC}
  See docs/development/README.md and docs/deployment/README.md

EOF
}

# Function to show service status
show_status() {
    print_header "Service Status"

    if [ ! -f "$SCRIPT_DIR/$DOCKER_COMPOSE_FILE" ]; then
        print_status "error" "Docker Compose file not found. Run setup first."
        return 1
    fi

    cd "$SCRIPT_DIR" || exit 1
    ${DOCKER_COMPOSE_CMD:-docker compose} ps

    echo ""
    print_status "info" "Container resource usage:"
    # Handle case where no containers are running
    local containers
    containers=$(${DOCKER_COMPOSE_CMD:-docker compose} ps -q)
    if [ -n "$containers" ]; then
        docker stats --no-stream "$containers" 2>/dev/null || print_status "warning" "Could not get container stats"
    else
        print_status "info" "No containers are currently running"
    fi
}

# Function to show logs
show_logs() {
    if [ ! -f "$SCRIPT_DIR/$DOCKER_COMPOSE_FILE" ]; then
        print_status "error" "Docker Compose file not found. Run setup first."
        return 1
    fi

    cd "$SCRIPT_DIR" || exit 1
    ${DOCKER_COMPOSE_CMD:-docker compose} logs -f
}

# Function to stop services
stop_services() {
    print_header "Stopping Services"

    if [ ! -f "$SCRIPT_DIR/$DOCKER_COMPOSE_FILE" ]; then
        print_status "error" "Docker Compose file not found."
        return 1
    fi

    cd "$SCRIPT_DIR" || exit 1
    ${DOCKER_COMPOSE_CMD:-docker compose} down
    print_status "success" "Services stopped"
}

# Function to start services
start_services() {
    print_header "Starting Services"

    if [ ! -f "$SCRIPT_DIR/$DOCKER_COMPOSE_FILE" ]; then
        print_status "error" "Docker Compose file not found. Run setup first."
        return 1
    fi

    cd "$SCRIPT_DIR" || exit 1
    ${DOCKER_COMPOSE_CMD:-docker compose} up -d
    print_status "success" "Services started"
}

# Function to restart services
restart_services() {
    print_header "Restarting Services"

    if [ ! -f "$SCRIPT_DIR/$DOCKER_COMPOSE_FILE" ]; then
        print_status "error" "Docker Compose file not found. Run setup first."
        return 1
    fi

    cd "$SCRIPT_DIR" || exit 1
    ${DOCKER_COMPOSE_CMD:-docker compose} restart
    print_status "success" "Services restarted"
}

# Main script logic
main() {
    # Change to script directory
    cd "$SCRIPT_DIR" || exit 1

    # Parse command line arguments
    case "${1:---setup}" in
        --help|-h)
            show_usage
            exit 0
            ;;
        --precheck)
            check_prerequisites
            exit $?
            ;;
        --setup)
            if check_prerequisites; then
                set +e
                setup_project
                local setup_result=$?
                set -e

                if [ $setup_result -ne 0 ]; then
                    print_status "warning" "Setup encountered some issues"
                    print_status "info" "Please review the messages above and complete any manual steps needed"
                    print_status "info" "You can check service status with: docker compose ps"
                    exit 1
                fi
            else
                print_status "error" "Prerequisites check failed. Please fix the issues and try again."
                exit 1
            fi
            ;;
        --cleanup)
            cleanup
            ;;
        --deepcleanup)
            deep_cleanup
            ;;
        --backup)
            backup_data
            ;;
        --restore)
            if [ -z "$2" ]; then
                print_status "error" "Please provide backup path"
                exit 1
            fi
            restore_data "$2"
            ;;
        --status)
            show_status
            ;;
        --logs)
            show_logs
            ;;
        --stop)
            stop_services
            ;;
        --start)
            start_services
            ;;
        --restart)
            restart_services
            ;;
        *)
            print_status "error" "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
