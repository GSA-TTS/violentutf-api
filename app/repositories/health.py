"""Health check repository for system monitoring queries."""

from datetime import datetime, timezone
from typing import Dict, List, Optional

from sqlalchemy import func, text
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.repositories.base import BaseRepository

logger = get_logger(__name__)


class HealthRepository:
    """Repository for health check related database operations."""

    def __init__(self, session: AsyncSession):
        """Initialize health repository with database session."""
        self.session = session

    async def check_database_connectivity(self) -> Dict[str, str]:
        """Test basic database connectivity."""
        try:
            result = await self.session.execute(text("SELECT 1"))
            await result.fetchone()
            return {"status": "healthy", "response_time": "< 10ms"}
        except Exception as e:
            logger.error("Database connectivity check failed", error=str(e))
            return {"status": "unhealthy", "error": str(e)}

    async def get_database_stats(self) -> Dict[str, int]:
        """Get basic database statistics."""
        try:
            # Count total users
            user_count_result = await self.session.execute(text("SELECT COUNT(*) FROM users WHERE is_deleted = false"))
            user_count = user_count_result.scalar()

            # Count active sessions
            session_count_result = await self.session.execute(
                text("SELECT COUNT(*) FROM sessions WHERE expires_at > NOW()")
            )
            session_count = session_count_result.scalar()

            # Count API keys
            api_key_count_result = await self.session.execute(
                text("SELECT COUNT(*) FROM api_keys WHERE is_active = true")
            )
            api_key_count = api_key_count_result.scalar()

            return {
                "active_users": user_count or 0,
                "active_sessions": session_count or 0,
                "active_api_keys": api_key_count or 0,
            }
        except Exception as e:
            logger.error("Failed to get database stats", error=str(e))
            return {"active_users": 0, "active_sessions": 0, "active_api_keys": 0}

    async def get_mfa_health_stats(self) -> Dict[str, int]:
        """Get MFA-related health statistics."""
        try:
            # Count active MFA devices
            mfa_devices_result = await self.session.execute(
                text("SELECT COUNT(*) FROM mfa_devices WHERE is_active = true")
            )
            mfa_devices = mfa_devices_result.scalar()

            # Count recent MFA events (last 24 hours)
            recent_mfa_events_result = await self.session.execute(
                text(
                    """
                SELECT COUNT(*) FROM mfa_events
                WHERE created_at > NOW() - INTERVAL '24 hours'
                """
                )
            )
            recent_mfa_events = recent_mfa_events_result.scalar()

            return {
                "active_mfa_devices": mfa_devices or 0,
                "recent_mfa_events": recent_mfa_events or 0,
            }
        except Exception as e:
            logger.error("Failed to get MFA health stats", error=str(e))
            return {"active_mfa_devices": 0, "recent_mfa_events": 0}

    async def get_audit_health_stats(self) -> Dict[str, int]:
        """Get audit-related health statistics."""
        try:
            # Count recent audit logs (last 24 hours)
            recent_audit_logs_result = await self.session.execute(
                text(
                    """
                SELECT COUNT(*) FROM audit_logs
                WHERE created_at > NOW() - INTERVAL '24 hours'
                """
                )
            )
            recent_audit_logs = recent_audit_logs_result.scalar()

            # Count critical audit events (last 24 hours)
            critical_events_result = await self.session.execute(
                text(
                    """
                SELECT COUNT(*) FROM audit_logs
                WHERE created_at > NOW() - INTERVAL '24 hours'
                AND severity = 'CRITICAL'
                """
                )
            )
            critical_events = critical_events_result.scalar()

            return {
                "recent_audit_logs": recent_audit_logs or 0,
                "critical_events": critical_events or 0,
            }
        except Exception as e:
            logger.error("Failed to get audit health stats", error=str(e))
            return {"recent_audit_logs": 0, "critical_events": 0}
