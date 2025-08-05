# Security Notes

## Vulnerability Status

### Fixed Vulnerabilities
1. **Bandit B104 - Bind All Interfaces**: Fixed by making server host configurable with secure default (127.0.0.1)
2. **Cryptography**: Upgraded from 42.0.8 to 44.0.1 to fix GHSA-h4gh-qq45-vh27 and GHSA-79v4-65xg-pq4g
3. **Gunicorn**: Upgraded from 21.2.0 to 23.0.0 to fix GHSA-w3h3-4rj7-4ph4 and GHSA-hc5x-x2vx-497g

### Known Issues
1. **Starlette 0.36.3**: Has known vulnerabilities (GHSA-f96h-pmfr-66vw, GHSA-2c2j-9gv5-cj73)
   - Cannot upgrade to 0.47.2 due to FastAPI 0.109.0 dependency constraints
   - Will be resolved when FastAPI is upgraded to a version compatible with newer Starlette

## Security Configuration

### Server Binding
By default, the application binds to localhost (127.0.0.1) for security. To run in Docker or production environments where external access is needed:

1. Set the `SERVER_HOST` environment variable:
   ```bash
   SERVER_HOST=0.0.0.0 python -m app.main
   ```

2. Or update the `.env` file:
   ```
   SERVER_HOST="0.0.0.0"
   ```

### Other Security Features
- JWT tokens with configurable expiration
- Argon2 password hashing with secure defaults
- Security headers middleware (CSP, HSTS, X-Frame-Options, etc.)
- Rate limiting on sensitive endpoints
- Request ID tracking for audit trails
- Structured logging for security events
