from __future__ import annotations

import json
from typing import TextIO

from escapewatch.models import AssessmentResult


class JSONFormatter:
    """Format assessment results as JSON."""

    def __init__(self, pretty: bool = True) -> None:
        self.pretty = pretty

    def format(self, result: AssessmentResult) -> str:
        indent = 2 if self.pretty else None
        return json.dumps(result.to_dict(), indent=indent, default=str)

    def write(self, result: AssessmentResult, output: TextIO) -> None:
        output.write(self.format(result))
        output.write("\n")
