"""Comprehensive unit tests for SessionRepository implementation."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.session import Session
from app.repositories.session import SessionRepository


class TestSessionRepository:
    """Comprehensive unit tests for SessionRepository implementation."""

    @pytest.fixture
    def session_repository(self, mock_session: AsyncMock) -> SessionRepository:
        """Create SessionRepository instance with mocked session."""
        return SessionRepository(mock_session)

    @pytest.fixture
    def sample_session(self, session_factory) -> Session:
        """Create a sample session for testing."""
        return session_factory.create(
            id="test-session-id",
            user_id=str(uuid.uuid4()),
            session_token="test_token_hash_with_32_characters_min",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            ip_address="127.0.0.1",
            device_info="Test Agent",
            is_active=True,
        )

    @pytest.fixture
    def expired_session(self, session_factory) -> Session:
        """Create an expired session for testing."""
        return session_factory.create(
            id="expired-session-id",
            user_id=str(uuid.uuid4()),
            session_token="expired_token_hash_32_characters_min",
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
            is_active=True,
        )

    @pytest.fixture
    def revoked_session(self, session_factory) -> Session:
        """Create a revoked session for testing."""
        session = session_factory.create(
            id="revoked-session-id",
            user_id=str(uuid.uuid4()),
            session_token="revoked_token_hash_32_characters_min",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            is_active=False,
        )
        session.revoked_at = datetime.now(timezone.utc) - timedelta(minutes=30)
        session.revoked_by = "admin"
        session.revocation_reason = "Security violation"
        return session

    # Repository Initialization Tests

    @pytest.mark.asyncio
    async def test_repository_initialization(self, mock_session: AsyncMock):
        """Test SessionRepository initialization."""
        repository = SessionRepository(mock_session)

        assert repository.session == mock_session
        assert repository.model == Session
        assert repository.logger is not None

    # get_by_token Tests

    @pytest.mark.asyncio
    async def test_get_by_token_valid_session(
        self,
        session_repository: SessionRepository,
        mock_session: AsyncMock,
        sample_session: Session,
        query_result_factory,
    ):
        """Test successful retrieval of valid session by token."""
        # Arrange
        with patch.object(sample_session, "is_valid", return_value=True):
            result_mock = query_result_factory(scalar_result=sample_session)
            mock_session.execute.return_value = result_mock

            # Act
            session = await session_repository.get_by_token("test_token_hash_with_32_characters_min")

            # Assert
            assert session is not None
            assert session.session_token == "test_token_hash_with_32_characters_min"
            assert session.is_active is True
            mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_by_token_invalid_session(
        self,
        session_repository: SessionRepository,
        mock_session: AsyncMock,
        sample_session: Session,
        query_result_factory,
    ):
        """Test retrieval of invalid session by token."""
        # Arrange
        with patch.object(sample_session, "is_valid", return_value=False):
            result_mock = query_result_factory(scalar_result=sample_session)
            mock_session.execute.return_value = result_mock

            # Act
            session = await session_repository.get_by_token("test_token_hash_with_32_characters_min")

            # Assert
            assert session is None
            mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_by_token_not_found(
        self, session_repository: SessionRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test get_by_token when session not found."""
        # Arrange
        result_mock = query_result_factory(scalar_result=None)
        mock_session.execute.return_value = result_mock

        # Act
        session = await session_repository.get_by_token("nonexistent_token")

        # Assert
        assert session is None
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_by_token_database_error(
        self, session_repository: SessionRepository, mock_session: AsyncMock, database_error_factory
    ):
        """Test get_by_token with database error."""
        # Arrange
        mock_session.execute.side_effect = database_error_factory("connection")

        # Act & Assert
        with pytest.raises(SQLAlchemyError):
            await session_repository.get_by_token("test_token")

    # get_user_sessions Tests

    @pytest.mark.asyncio
    async def test_get_user_sessions_active_only(
        self, session_repository: SessionRepository, mock_session: AsyncMock, session_factory, query_result_factory
    ):
        """Test getting active user sessions only."""
        # Arrange
        user_id = uuid.uuid4()
        active_sessions = session_factory.create_batch(3, user_id=str(user_id), is_active=True)

        scalars_mock = MagicMock()
        scalars_mock.all.return_value = active_sessions
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        mock_session.execute.return_value = result_mock

        # Act
        sessions = await session_repository.get_user_sessions(user_id, include_inactive=False)

        # Assert
        assert len(sessions) == 3
        assert all(session.user_id == str(user_id) for session in sessions)
        assert all(session.is_active for session in sessions)
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_user_sessions_include_inactive(
        self, session_repository: SessionRepository, mock_session: AsyncMock, session_factory, query_result_factory
    ):
        """Test getting user sessions including inactive ones."""
        # Arrange
        user_id = uuid.uuid4()
        all_sessions = [
            session_factory.create(user_id=str(user_id), is_active=True),
            session_factory.create(user_id=str(user_id), is_active=False),
            session_factory.create(user_id=str(user_id), is_active=True),
        ]

        scalars_mock = MagicMock()
        scalars_mock.all.return_value = all_sessions
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        mock_session.execute.return_value = result_mock

        # Act
        sessions = await session_repository.get_user_sessions(user_id, include_inactive=True)

        # Assert
        assert len(sessions) == 3
        assert all(session.user_id == str(user_id) for session in sessions)
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_user_sessions_empty_result(
        self, session_repository: SessionRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test getting user sessions when no sessions exist."""
        # Arrange
        user_id = uuid.uuid4()

        scalars_mock = MagicMock()
        scalars_mock.all.return_value = []
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        mock_session.execute.return_value = result_mock

        # Act
        sessions = await session_repository.get_user_sessions(user_id)

        # Assert
        assert sessions == []
        mock_session.execute.assert_called_once()

    # get_active_sessions Tests

    @pytest.mark.asyncio
    async def test_get_active_sessions_success(
        self, session_repository: SessionRepository, mock_session: AsyncMock, session_factory, query_result_factory
    ):
        """Test getting all active sessions."""
        # Arrange
        active_sessions = session_factory.create_batch(5, is_active=True)

        scalars_mock = MagicMock()
        scalars_mock.all.return_value = active_sessions
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        mock_session.execute.return_value = result_mock

        # Act
        sessions = await session_repository.get_active_sessions(limit=10)

        # Assert
        assert len(sessions) == 5
        assert all(session.is_active for session in sessions)
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_active_sessions_with_limit(
        self, session_repository: SessionRepository, mock_session: AsyncMock, session_factory, query_result_factory
    ):
        """Test getting active sessions with limit."""
        # Arrange
        active_sessions = session_factory.create_batch(3, is_active=True)

        scalars_mock = MagicMock()
        scalars_mock.all.return_value = active_sessions
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        mock_session.execute.return_value = result_mock

        # Act
        sessions = await session_repository.get_active_sessions(limit=5)

        # Assert
        assert len(sessions) == 3
        mock_session.execute.assert_called_once()

    # revoke_session Tests

    @pytest.mark.asyncio
    async def test_revoke_session_success(
        self, session_repository: SessionRepository, mock_session: AsyncMock, sample_session: Session
    ):
        """Test successful session revocation."""
        # Arrange
        session_id = uuid.uuid4()
        sample_session.revoked_at = None  # Ensure not already revoked

        with (
            patch.object(session_repository, "get", return_value=sample_session),
            patch.object(sample_session, "revoke") as mock_revoke,
        ):

            # Act
            result = await session_repository.revoke_session(session_id, "admin", "Test revocation")

            # Assert
            assert result is True
            mock_revoke.assert_called_once_with("admin", "Test revocation")
            mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_revoke_session_not_found(self, session_repository: SessionRepository, mock_session: AsyncMock):
        """Test revoking non-existent session."""
        # Arrange
        session_id = uuid.uuid4()

        with patch.object(session_repository, "get", return_value=None):
            # Act
            result = await session_repository.revoke_session(session_id, "admin")

            # Assert
            assert result is False
            mock_session.commit.assert_not_called()

    @pytest.mark.asyncio
    async def test_revoke_session_already_revoked(
        self, session_repository: SessionRepository, mock_session: AsyncMock, revoked_session: Session
    ):
        """Test revoking already revoked session."""
        # Arrange
        session_id = uuid.uuid4()

        with patch.object(session_repository, "get", return_value=revoked_session):
            # Act
            result = await session_repository.revoke_session(session_id, "admin")

            # Assert
            assert result is False
            mock_session.commit.assert_not_called()

    @pytest.mark.asyncio
    async def test_revoke_session_database_error(
        self,
        session_repository: SessionRepository,
        mock_session: AsyncMock,
        sample_session: Session,
        database_error_factory,
    ):
        """Test revoke_session with database error."""
        # Arrange
        session_id = uuid.uuid4()
        sample_session.revoked_at = None
        mock_session.commit.side_effect = database_error_factory("connection")

        with (
            patch.object(session_repository, "get", return_value=sample_session),
            patch.object(sample_session, "revoke"),
        ):

            # Act & Assert
            with pytest.raises(SQLAlchemyError):
                await session_repository.revoke_session(session_id, "admin")

            mock_session.rollback.assert_called_once()

    # revoke_user_sessions Tests

    @pytest.mark.asyncio
    async def test_revoke_user_sessions_success(self, session_repository: SessionRepository, mock_session: AsyncMock):
        """Test successful revocation of all user sessions."""
        # Arrange
        user_id = uuid.uuid4()

        result_mock = MagicMock()
        result_mock.rowcount = 3
        mock_session.execute.return_value = result_mock

        # Act
        revoked_count = await session_repository.revoke_user_sessions(user_id, "admin", "Account compromised")

        # Assert
        assert revoked_count == 3
        mock_session.execute.assert_called_once()
        mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_revoke_user_sessions_no_sessions(
        self, session_repository: SessionRepository, mock_session: AsyncMock
    ):
        """Test revoking user sessions when no active sessions exist."""
        # Arrange
        user_id = uuid.uuid4()

        result_mock = MagicMock()
        result_mock.rowcount = 0
        mock_session.execute.return_value = result_mock

        # Act
        revoked_count = await session_repository.revoke_user_sessions(user_id, "admin")

        # Assert
        assert revoked_count == 0
        mock_session.execute.assert_called_once()
        mock_session.commit.assert_called_once()

    # cleanup_expired_sessions Tests

    @pytest.mark.asyncio
    async def test_cleanup_expired_sessions_success(
        self, session_repository: SessionRepository, mock_session: AsyncMock
    ):
        """Test successful cleanup of expired sessions."""
        # Arrange
        result_mock = MagicMock()
        result_mock.rowcount = 5
        mock_session.execute.return_value = result_mock

        # Act
        cleaned_count = await session_repository.cleanup_expired_sessions(batch_size=100)

        # Assert
        assert cleaned_count == 5
        mock_session.execute.assert_called_once()
        mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_expired_sessions_no_expired(
        self, session_repository: SessionRepository, mock_session: AsyncMock
    ):
        """Test cleanup when no expired sessions exist."""
        # Arrange
        result_mock = MagicMock()
        result_mock.rowcount = 0
        mock_session.execute.return_value = result_mock

        # Act
        cleaned_count = await session_repository.cleanup_expired_sessions()

        # Assert
        assert cleaned_count == 0
        mock_session.execute.assert_called_once()
        mock_session.commit.assert_called_once()

    # update_session_activity Tests

    @pytest.mark.asyncio
    async def test_update_session_activity_success(
        self, session_repository: SessionRepository, mock_session: AsyncMock, sample_session: Session
    ):
        """Test successful session activity update."""
        # Arrange
        with (
            patch.object(session_repository, "get_by_token", return_value=sample_session),
            patch.object(sample_session, "update_activity") as mock_update,
        ):

            # Act
            result = await session_repository.update_session_activity("test_token", "192.168.1.1")

            # Assert
            assert result is True
            mock_update.assert_called_once_with("192.168.1.1")
            mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_session_activity_session_not_found(
        self, session_repository: SessionRepository, mock_session: AsyncMock
    ):
        """Test updating activity for non-existent session."""
        # Arrange
        with patch.object(session_repository, "get_by_token", return_value=None):
            # Act
            result = await session_repository.update_session_activity("nonexistent_token")

            # Assert
            assert result is False
            mock_session.commit.assert_not_called()

    # extend_session Tests

    @pytest.mark.asyncio
    async def test_extend_session_success(
        self, session_repository: SessionRepository, mock_session: AsyncMock, sample_session: Session
    ):
        """Test successful session extension."""
        # Arrange
        with (
            patch.object(session_repository, "get_by_token", return_value=sample_session),
            patch.object(sample_session, "extend_session") as mock_extend,
        ):

            # Act
            result = await session_repository.extend_session("test_token", extension_minutes=120)

            # Assert
            assert result is True
            mock_extend.assert_called_once()
            mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_extend_session_not_found(self, session_repository: SessionRepository, mock_session: AsyncMock):
        """Test extending non-existent session."""
        # Arrange
        with patch.object(session_repository, "get_by_token", return_value=None):
            # Act
            result = await session_repository.extend_session("nonexistent_token")

            # Assert
            assert result is False
            mock_session.commit.assert_not_called()

    # get_sessions_by_ip Tests

    @pytest.mark.asyncio
    async def test_get_sessions_by_ip_success(
        self, session_repository: SessionRepository, mock_session: AsyncMock, session_factory
    ):
        """Test getting sessions by IP address."""
        # Arrange
        ip_address = "192.168.1.100"
        sessions = session_factory.create_batch(2, ip_address=ip_address)

        scalars_mock = MagicMock()
        scalars_mock.all.return_value = sessions
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        mock_session.execute.return_value = result_mock

        # Act
        result_sessions = await session_repository.get_sessions_by_ip(ip_address, limit=10)

        # Assert
        assert len(result_sessions) == 2
        assert all(session.ip_address == ip_address for session in result_sessions)
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_sessions_by_ip_empty_result(
        self, session_repository: SessionRepository, mock_session: AsyncMock
    ):
        """Test getting sessions by IP when none exist."""
        # Arrange
        scalars_mock = MagicMock()
        scalars_mock.all.return_value = []
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        mock_session.execute.return_value = result_mock

        # Act
        sessions = await session_repository.get_sessions_by_ip("10.0.0.1")

        # Assert
        assert sessions == []
        mock_session.execute.assert_called_once()

    # get_statistics Tests

    @pytest.mark.asyncio
    async def test_get_statistics_success(
        self, session_repository: SessionRepository, mock_session: AsyncMock, session_factory
    ):
        """Test getting session statistics."""
        # Arrange
        # Mock multiple queries for different statistics
        all_sessions = session_factory.create_batch(10)
        active_sessions = session_factory.create_batch(5)
        expired_sessions = session_factory.create_batch(3)
        revoked_sessions = session_factory.create_batch(2)
        today_sessions = session_factory.create_batch(4)

        # Create mock results for each query
        scalars_mocks = []
        for sessions_list in [all_sessions, active_sessions, expired_sessions, revoked_sessions, today_sessions]:
            scalars_mock = MagicMock()
            scalars_mock.all.return_value = sessions_list
            scalars_mocks.append(scalars_mock)

        result_mocks = []
        for scalars_mock in scalars_mocks:
            result_mock = MagicMock()
            result_mock.scalars.return_value = scalars_mock
            result_mocks.append(result_mock)

        mock_session.execute.side_effect = result_mocks

        # Act
        stats = await session_repository.get_statistics()

        # Assert
        assert stats["total_sessions"] == 10
        assert stats["active_sessions"] == 5
        assert stats["expired_sessions"] == 3
        assert stats["revoked_sessions"] == 2
        assert stats["sessions_created_today"] == 4
        assert mock_session.execute.call_count == 5

    # Interface Methods Tests

    @pytest.mark.asyncio
    async def test_create_session_interface_method(
        self, session_repository: SessionRepository, mock_session: AsyncMock, session_factory
    ):
        """Test create_session interface method."""
        # Arrange
        created_session = session_factory.create()

        with patch.object(session_repository, "create", return_value=created_session) as mock_create:
            # Act
            session = await session_repository.create_session(
                user_id=str(uuid.uuid4()),
                token="test_token_32_characters_minimum_len",
                expires_at=datetime.now(timezone.utc).isoformat(),
                ip_address="127.0.0.1",
                user_agent="Test Agent",
            )

            # Assert
            assert session is not None
            mock_create.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_active_sessions_interface_method(
        self, session_repository: SessionRepository, mock_session: AsyncMock, session_factory
    ):
        """Test get_active_sessions interface method."""
        # Arrange
        user_id = str(uuid.uuid4())
        active_sessions = session_factory.create_batch(3, user_id=user_id, is_active=True)

        with patch.object(session_repository, "get_user_sessions", return_value=active_sessions) as mock_get:
            # Act
            sessions = await session_repository.get_active_sessions(user_id)

            # Assert
            assert len(sessions) == 3
            mock_get.assert_called_once_with(uuid.UUID(user_id), include_inactive=False)

    @pytest.mark.asyncio
    async def test_get_user_sessions_interface_method(
        self, session_repository: SessionRepository, mock_session: AsyncMock, session_factory
    ):
        """Test get_user_sessions_interface interface method."""
        # Arrange
        user_id = str(uuid.uuid4())
        user_sessions = session_factory.create_batch(5, user_id=user_id)

        with patch.object(session_repository, "get_user_sessions", return_value=user_sessions) as mock_get:
            # Act
            sessions = await session_repository.get_user_sessions_interface(user_id, limit=3)

            # Assert
            assert len(sessions) == 3  # Limited to 3
            mock_get.assert_called_once_with(uuid.UUID(user_id), include_inactive=True)

    @pytest.mark.asyncio
    async def test_invalidate_session_interface_method(
        self, session_repository: SessionRepository, mock_session: AsyncMock
    ):
        """Test invalidate_session interface method."""
        # Arrange
        session_id = str(uuid.uuid4())

        with patch.object(session_repository, "revoke_session", return_value=True) as mock_revoke:
            # Act
            result = await session_repository.invalidate_session(session_id)

            # Assert
            assert result is True
            mock_revoke.assert_called_once_with(uuid.UUID(session_id), "system", "Session invalidated")

    @pytest.mark.asyncio
    async def test_invalidate_user_sessions_exclude_session(
        self, session_repository: SessionRepository, mock_session: AsyncMock, session_factory
    ):
        """Test invalidate_user_sessions with excluded session."""
        # Arrange
        user_id = str(uuid.uuid4())
        exclude_session_id = str(uuid.uuid4())

        # Create sessions with different IDs
        sessions = [
            session_factory.create(id=exclude_session_id, user_id=user_id),
            session_factory.create(id=str(uuid.uuid4()), user_id=user_id),
            session_factory.create(id=str(uuid.uuid4()), user_id=user_id),
        ]

        # Mock revoke_session to return True only for sessions that should be revoked
        def mock_revoke_side_effect(session_id, *args, **kwargs):
            return str(session_id) != exclude_session_id

        with (
            patch.object(session_repository, "get_user_sessions", return_value=sessions),
            patch.object(session_repository, "revoke_session", side_effect=mock_revoke_side_effect) as mock_revoke,
        ):

            # Act
            count = await session_repository.invalidate_user_sessions(user_id, exclude_session_id=exclude_session_id)

            # Assert
            assert count == 2  # Two sessions revoked (excluding one)
            assert mock_revoke.call_count == 3  # Called for all sessions, but only 2 return True

    @pytest.mark.asyncio
    async def test_invalidate_user_sessions_all(self, session_repository: SessionRepository, mock_session: AsyncMock):
        """Test invalidate_user_sessions for all sessions."""
        # Arrange
        user_id = str(uuid.uuid4())

        with patch.object(session_repository, "revoke_user_sessions", return_value=5) as mock_revoke:
            # Act
            count = await session_repository.invalidate_user_sessions(user_id)

            # Assert
            assert count == 5
            mock_revoke.assert_called_once_with(uuid.UUID(user_id), "system", "All sessions invalidated")

    @pytest.mark.asyncio
    async def test_extend_session_interface_method(
        self, session_repository: SessionRepository, mock_session: AsyncMock, sample_session: Session
    ):
        """Test extend_session interface method."""
        # Arrange
        session_id = str(uuid.uuid4())
        extension = timedelta(hours=2)

        with (
            patch.object(session_repository, "get", return_value=sample_session),
            patch.object(sample_session, "extend_session") as mock_extend,
        ):

            # Act
            session = await session_repository.extend_session(session_id, extension)

            # Assert
            assert session is not None
            mock_extend.assert_called_once()
            mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_extend_session_interface_method_not_found(
        self, session_repository: SessionRepository, mock_session: AsyncMock
    ):
        """Test extend_session interface method when session not found."""
        # Arrange
        session_id = str(uuid.uuid4())
        extension = timedelta(hours=2)

        with patch.object(session_repository, "get", return_value=None):
            # Act
            session = await session_repository.extend_session(session_id, extension)

            # Assert
            assert session is None
            mock_session.commit.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_session_statistics_interface_method(
        self, session_repository: SessionRepository, mock_session: AsyncMock
    ):
        """Test get_session_statistics interface method."""
        # Arrange
        stats = {
            "total_sessions": 100,
            "active_sessions": 50,
            "expired_sessions": 30,
            "revoked_sessions": 20,
            "sessions_created_today": 10,
        }

        with patch.object(session_repository, "get_statistics", return_value=stats) as mock_stats:
            # Act
            result = await session_repository.get_session_statistics()

            # Assert
            assert result == stats
            mock_stats.assert_called_once()

    # Error Handling and Edge Cases

    @pytest.mark.asyncio
    async def test_database_rollback_on_error(
        self,
        session_repository: SessionRepository,
        mock_session: AsyncMock,
        sample_session: Session,
        database_error_factory,
    ):
        """Test database rollback on error."""
        # Arrange
        mock_session.commit.side_effect = database_error_factory("connection")

        with (
            patch.object(session_repository, "get_by_token", return_value=sample_session),
            patch.object(sample_session, "update_activity"),
        ):

            # Act & Assert
            with pytest.raises(SQLAlchemyError):
                await session_repository.update_session_activity("test_token")

            mock_session.rollback.assert_called_once()

    @pytest.mark.asyncio
    async def test_large_batch_size_handling(self, session_repository: SessionRepository, mock_session: AsyncMock):
        """Test handling of large batch sizes in cleanup."""
        # Arrange
        result_mock = MagicMock()
        result_mock.rowcount = 10000
        mock_session.execute.return_value = result_mock

        # Act
        cleaned_count = await session_repository.cleanup_expired_sessions(batch_size=10000)

        # Assert
        assert cleaned_count == 10000
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_uuid_conversion_handling(self, session_repository: SessionRepository, mock_session: AsyncMock):
        """Test proper UUID conversion in interface methods."""
        # Test with valid UUID string
        valid_uuid = str(uuid.uuid4())

        with patch.object(session_repository, "get_user_sessions", return_value=[]):
            await session_repository.get_active_sessions(valid_uuid)

        # Test with invalid UUID string should raise ValueError
        with pytest.raises(ValueError):
            await session_repository.get_active_sessions("invalid-uuid")

    @pytest.mark.asyncio
    async def test_datetime_iso_conversion(
        self, session_repository: SessionRepository, mock_session: AsyncMock, session_factory
    ):
        """Test datetime ISO string conversion in create_session."""
        # Arrange
        created_session = session_factory.create()

        with patch.object(session_repository, "create", return_value=created_session):
            # Test with ISO string
            await session_repository.create_session(
                user_id=str(uuid.uuid4()),
                token="test_token_32_characters_minimum_len",
                expires_at="2024-01-01T12:00:00",
                ip_address="127.0.0.1",
            )

            # Test without expires_at
            await session_repository.create_session(
                user_id=str(uuid.uuid4()), token="test_token_32_characters_minimum_len", ip_address="127.0.0.1"
            )
