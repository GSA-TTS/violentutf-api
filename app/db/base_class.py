"""Base class for SQLAlchemy declarative models - SQLAlchemy 2.0 Compatible."""

from typing import Any, Type

from sqlalchemy.orm import DeclarativeBase, declared_attr


class Base(DeclarativeBase):
    """Base class for all database models."""

    id: Any

    # Generate __tablename__ automatically from class name
    @declared_attr.directive
    @classmethod
    def __tablename__(cls: Type["Base"]) -> str:
        """Generate table name from class name."""
        # Convert CamelCase to snake_case
        name = cls.__name__
        # Handle acronyms and maintain them in uppercase
        result = []
        for i, char in enumerate(name):
            if i > 0 and char.isupper():
                # Check if previous char is lowercase or next char (if exists) is lowercase
                if name[i - 1].islower() or (i + 1 < len(name) and name[i + 1].islower()):
                    result.append("_")
            result.append(char.lower())
        return "".join(result)
