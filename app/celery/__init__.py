"""Celery package for async task processing."""

from .celery import celery_app

__all__ = ["celery_app"]
