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
        """Check if a path is writable without modifying it.

        os.access(W_OK) checks DAC permissions against the real UID, but UID 0
        bypasses DAC entirely — so as root it returns True for almost any path
        regardless of its mode, producing false-positive "writable" findings.
        For root, the only thing that actually gates a write is whether the
        backing mount is read-only, so we consult the mount flags instead.
        """
        import os

        if os.geteuid() != 0:
            return os.access(path, os.W_OK)

        ro = self._is_on_readonly_mount(path)
        if ro is None:
            # Could not determine the backing mount — fall back to os.access.
            return os.access(path, os.W_OK)
        return not ro

    def _is_on_readonly_mount(self, path: str) -> bool | None:
        """Return True/False if `path`'s backing mount is read-only, else None.

        Resolves the longest mountpoint in /proc/mounts that is a prefix of
        `path` and inspects its mount options for the `ro` flag. Returns None
        when /proc/mounts is unavailable or no mountpoint matches.
        """
        import os

        mounts = self._read_file("/proc/mounts")
        if not mounts:
            return None

        resolved = os.path.realpath(path)
        best_mp = ""
        best_ro: bool | None = None
        for line in mounts.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            mountpoint = parts[1]
            options = parts[3].split(",")
            if resolved == mountpoint or resolved.startswith(
                mountpoint.rstrip("/") + "/"
            ) or mountpoint == "/":
                if len(mountpoint) >= len(best_mp):
                    best_mp = mountpoint
                    best_ro = "ro" in options
        return best_ro
