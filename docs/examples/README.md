# Security Feature Examples

This directory contains example endpoints demonstrating the security features implemented in ViolentUTF API. These examples are for documentation and learning purposes only and should not be included in production deployments.

## Example Endpoints

### 1. Circuit Breaker Examples (`example_circuit_breaker.py`)
Demonstrates how to protect external API calls with circuit breaker patterns:
- Weather API endpoint with automatic fallback
- Payment processing with manual circuit breaker control
- Database operations with circuit protection
- Cache operations with fallback to None
- Circuit breaker statistics and management

### 2. Request Signing Examples (`example_request_signed.py`)
Shows HMAC-SHA256 request signing for sensitive operations:
- Transfer endpoint requiring valid signature
- Admin actions with signature verification
- Webhook endpoints with request validation
- Signature generation examples
- Common error scenarios

### 3. Field Sanitization Examples (`example_sanitized.py`)
Demonstrates input sanitization with bleach:
- HTML content sanitization
- Markdown processing with allowed tags
- User profile data cleaning
- Comment system with XSS prevention
- Custom sanitization rules

### 4. SQL Injection Prevention Examples (`example_sql_safe.py`)
Shows various SQL injection prevention techniques:
- **UNSAFE example** - Intentionally vulnerable endpoint for comparison
- Basic parameterized queries
- SafeQuery builder pattern
- Pre-defined query templates
- Dynamic query construction with validation

## Usage

These examples are meant to be studied and adapted for your specific use cases. Each file contains:
- Detailed docstrings explaining the security feature
- Both secure and insecure examples (clearly marked)
- Common patterns and best practices
- Integration with the broader security framework

## Security Notes

1. **Never deploy example endpoints to production** - They may contain intentionally vulnerable code for demonstration
2. **Always adapt examples to your needs** - Don't copy-paste without understanding
3. **Test thoroughly** - Security features need comprehensive testing
4. **Monitor in production** - Use logging and metrics to track security events

## Running Examples Locally

To test these examples in a development environment:

1. Copy the desired example file to `app/api/endpoints/`
2. Import and register the router in `app/api/routes.py`
3. Start the development server
4. Access the endpoints via the API documentation at `/docs`

Remember to remove example endpoints before deploying to production!
