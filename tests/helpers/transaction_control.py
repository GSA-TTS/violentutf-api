"""Transaction control helpers for integration tests."""

from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession


class TransactionControlMixin(Protocol):
    """Mixin to control transaction commits in services during testing."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._auto_commit = True

    def set_auto_commit(self, auto_commit: bool) -> None:
        """Control whether service should auto-commit transactions."""
        self._auto_commit = auto_commit

    async def _commit_if_enabled(self) -> None:
        """Commit transaction only if auto-commit is enabled."""
        if self._auto_commit and hasattr(self, "session") and self.session:
            await self.session.commit()

    async def _rollback_if_enabled(self) -> None:
        """Rollback transaction only if auto-commit is enabled."""
        if self._auto_commit and hasattr(self, "session") and self.session:
            await self.session.rollback()


def disable_auto_commit(service) -> None:
    """Disable auto-commit for a service instance during testing."""
    if hasattr(service, "set_auto_commit"):
        service.set_auto_commit(False)
    elif hasattr(service, "_auto_commit"):
        service._auto_commit = False


def enable_auto_commit(service) -> None:
    """Re-enable auto-commit for a service instance."""
    if hasattr(service, "set_auto_commit"):
        service.set_auto_commit(True)
    elif hasattr(service, "_auto_commit"):
        service._auto_commit = True


class MockAsyncSession(AsyncSession):
    """Mock session that tracks commit calls but doesn't actually commit."""

    def __init__(self, session: AsyncSession):
        self._wrapped_session = session
        self.commit_called = False
        self.rollback_called = False

    async def commit(self) -> None:
        """Track commit calls but don't actually commit."""
        self.commit_called = True
        # Don't actually commit - let the test fixture manage transaction

    async def rollback(self) -> None:
        """Track rollback calls and delegate to wrapped session."""
        self.rollback_called = True
        await self._wrapped_session.rollback()

    def __getattr__(self, name):
        """Delegate all other calls to wrapped session."""
        return getattr(self._wrapped_session, name)
