# ViolentUTF API Setup Guide

## Quick Start

```bash
# Full setup with all features
./setup_violentutf.sh --setup

# Or just run without arguments (default is --setup)
./setup_violentutf.sh
```

## Available Scripts

### 1. **setup_violentutf.sh** (Main Setup Script)
The comprehensive setup script with full feature set:

```bash
# Quick start - full setup
./setup_violentutf.sh

# Or explicitly specify setup
./setup_violentutf.sh --setup
```

**All Options:**
```bash
# Prerequisites and setup
./setup_violentutf.sh --precheck    # Check prerequisites only
./setup_violentutf.sh --setup       # Full setup (default)

# Service management
./setup_violentutf.sh --status      # Check service status
./setup_violentutf.sh --logs        # View logs
./setup_violentutf.sh --stop        # Stop services
./setup_violentutf.sh --start       # Start services
./setup_violentutf.sh --restart     # Restart services

# Backup and restore
./setup_violentutf.sh --backup              # Create backup
./setup_violentutf.sh --restore backup.tar  # Restore from backup

# Cleanup
./setup_violentutf.sh --cleanup     # Clean but preserve data
./setup_violentutf.sh --deepcleanup # Remove everything

# Help
./setup_violentutf.sh --help        # Show help message
```

**Features:**
- ✅ Complete Docker environment setup
- ✅ Database initialization with all tables
- ✅ Admin user creation with secure credentials
- ✅ Nginx reverse proxy configuration
- ✅ Service health checks
- ✅ Backup/restore functionality
- ✅ Service management commands
- ✅ Clean terminal output (auto-detects color support)
- ✅ Displays credentials at the end of setup

### 2. **show_credentials.sh** (View Saved Credentials)
Display saved admin credentials after setup:

```bash
./show_credentials.sh
```

**Shows:**
- Admin username, password, and API key
- Service URLs
- Example curl commands for testing

## What Gets Set Up

1. **Docker Services:**
   - API server (FastAPI)
   - PostgreSQL database
   - Redis cache
   - Nginx reverse proxy

2. **Database:**
   - 17 tables including:
     - User management
     - API keys
     - Sessions
     - Audit logs
     - MFA (Multi-Factor Authentication)
     - OAuth2 applications
     - Roles and permissions

3. **Admin User:**
   - Username: `admin`
   - Password: (generated securely)
   - API Key: (generated securely)

4. **URLs:**
   - API: http://localhost:8000
   - API Docs: http://localhost:8000/docs
   - Health Check: http://localhost:8000/api/v1/health
   - Via Nginx: http://localhost:80

## Security Notes

- All passwords and API keys are generated securely using cryptographically strong random functions
- Credentials are saved in `.admin_credentials` (chmod 600)
- Never commit `.env` or `.admin_credentials` to version control
- Default secrets in `.env.example` are automatically replaced during setup

## Troubleshooting

### Weird Text/Escape Codes
The scripts automatically detect terminal color support. If you see escape codes:
- Use `setup_clean.sh` instead
- Or set environment: `export TERM=dumb`

### Services Not Starting
```bash
# Check status
./setup_violentutf.sh --status

# View logs
./setup_violentutf.sh --logs

# Restart services
./setup_violentutf.sh --restart
```

### Database Issues
```bash
# Clean up and start fresh
./setup_violentutf.sh --cleanup
./setup_violentutf.sh --setup
```

### Port Conflicts
If ports 8000 or 80 are in use, modify `.env`:
```bash
API_PORT=8001
NGINX_PORT=8080
```

## Testing the API

After setup, test the API:

```bash
# Health check
curl http://localhost:8000/api/v1/health

# Login (replace with your generated password)
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your-generated-password"}'
```

## Next Steps

1. View the API documentation: http://localhost:8000/docs
2. Check credentials: `./show_credentials.sh`
3. Monitor services: `./setup_violentutf.sh --status`
4. Create additional users via the API
5. Configure your security policies

## Support

For issues or questions:
1. Check service logs: `./setup_violentutf.sh --logs`
2. Review this guide
3. Check the main documentation in `/docs`
