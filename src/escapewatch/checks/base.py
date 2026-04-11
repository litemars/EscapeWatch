from __future__ import annotations

import abc
from typing import ClassVar

from escapewatch.models import Category, EnvironmentInfo, Finding


class CheckRegistry:
    """Registry for all available check classes."""

    _checks: ClassVar[list[type[BaseCheck]]] = []

    @classmethod
    def register(cls, check_class: type[BaseCheck]) -> type[BaseCheck]:
        """Register a check class."""
        cls._checks.append(check_class)
        return check_class

    @classmethod
    def all_checks(cls) -> list[type[BaseCheck]]:
        return list(cls._checks)

    @classmethod
    def checks_for_category(cls, category: Category) -> list[type[BaseCheck]]:
        return [c for c in cls._checks if c.category == category]

    @classmethod
    def clear(cls) -> None:
        """Clear the registry (for testing)."""
        cls._checks.clear()


def register_check(cls: type[BaseCheck]) -> type[BaseCheck]:
    """Decorator to register a check class."""
    CheckRegistry.register(cls)
    return cls


class BaseCheck(abc.ABC):
    """Abstract base class for all security checks."""

    name: ClassVar[str] = ""
    description: ClassVar[str] = ""
    category: ClassVar[Category]

    def __init__(self, environment: EnvironmentInfo) -> None:
        self.environment = environment

    @abc.abstractmethod
    def run(self) -> list[Finding]:
        """Execute the check and return any findings."""
        ...

    def _read_file(self, path: str) -> str | None:
        """Safely read a file, returning None on failure."""
        try:
            with open(path) as f:
                return f.read()
        except OSError:
            return None

    def _path_exists(self, path: str) -> bool:
        """Check if a path exists without raising."""
        try:
            from pathlib import Path

            return Path(path).exists()
        except OSError:
            return False

    def _is_writable(self, path: str) -> bool:
        """Check if a path is writable without modifying it."""
        import os

        return os.access(path, os.W_OK)
