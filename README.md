# ViolentUTF API

Standalone AI red-teaming API service for enterprise security testing.

## Overview

ViolentUTF API is a comprehensive security testing platform that provides:
- AI model vulnerability assessment
- Red-teaming capabilities
- Security scan management
- Vulnerability taxonomy and tracking

## Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Or using Poetry
poetry install
```

## Development

```bash
# Run tests
pytest

# Run with hot-reload
uvicorn app.main:app --reload
```

## Docker

```bash
# Build image
docker build -t violentutf-api .

# Run container
docker run -p 8000:8000 violentutf-api
```

## License

MIT License - See LICENSE file for details.
