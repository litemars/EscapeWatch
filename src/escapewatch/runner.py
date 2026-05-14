from __future__ import annotations

import logging
import sys

from escapewatch.checks.base import CheckRegistry
from escapewatch.environment import detect_environment
from escapewatch.models import AssessmentResult, Category, EnvironmentInfo

logger = logging.getLogger("escapewatch")

# Import check modules to trigger registration
import escapewatch.checks.privileges  # noqa: F401
import escapewatch.checks.filesystem  # noqa: F401
import escapewatch.checks.namespaces  # noqa: F401
import escapewatch.checks.kubernetes  # noqa: F401
import escapewatch.checks.cloud  # noqa: F401
import escapewatch.checks.sockets  # noqa: F401
import escapewatch.checks.runtime_versions  # noqa: F401
import escapewatch.checks.kernel  # noqa: F401
import escapewatch.checks.chains  # noqa: F401


def run_assessment(
    categories: list[Category] | None = None,
    environment: EnvironmentInfo | None = None,
) -> AssessmentResult:
    """Run the full assessment pipeline.

    Args:
        categories: Optional list of categories to restrict checks to.
                    If None, all categories are checked.
        environment: Optional pre-detected environment (for testing).
    """
    if environment is None:
        environment = detect_environment()

    result = AssessmentResult(environment=environment)

    checks = CheckRegistry.all_checks()
    if categories:
        checks = [c for c in checks if c.category in categories]

    for check_class in checks:
        try:
            check = check_class(environment)
            findings = check.run()
            result.findings.extend(findings)
        except Exception:
            # Log the error so check bugs are visible instead of silently
            # swallowed, but don't let one check crash the whole assessment.
            logger.warning(
                "Check %s failed: %s",
                getattr(check_class, "name", check_class.__name__),
                sys.exc_info()[1],
                exc_info=True,
            )

    return result
