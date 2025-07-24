"""Main entry point for ViolentUTF API."""

from fastapi import FastAPI

# Create FastAPI instance
app = FastAPI(
    title="ViolentUTF API",
    description="Enterprise-grade AI red-teaming API service",
    version="0.1.0",
)


@app.get("/")
async def root() -> dict[str, str]:
    """Root endpoint."""
    return {"message": "Welcome to ViolentUTF API", "version": "0.1.0"}


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy"}


if __name__ == "__main__":
    import os

    import uvicorn

    # Use environment variable for host to avoid hardcoding
    host = os.getenv("API_HOST", "127.0.0.1")
    port = int(os.getenv("API_PORT", "8000"))

    uvicorn.run(app, host=host, port=port)
