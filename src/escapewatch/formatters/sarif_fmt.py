from __future__ import annotations

import json
from typing import TextIO

from escapewatch import __version__
from escapewatch.models import AssessmentResult, Finding


class SARIFFormatter:
    """Format assessment results as SARIF v2.1.0."""

    SARIF_VERSION = "2.1.0"
    SARIF_SCHEMA = (
        "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/"
        "schemas/sarif-schema-2.1.0.json"
    )

    def format(self, result: AssessmentResult) -> str:
        sarif = {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [self._build_run(result)],
        }
        return json.dumps(sarif, indent=2, default=str)

    def write(self, result: AssessmentResult, output: TextIO) -> None:
        output.write(self.format(result))
        output.write("\n")

    def _build_run(self, result: AssessmentResult) -> dict:
        rules = []
        results = []
        rule_map: dict[str, dict] = {}  # id -> rule dict

        for finding in result.findings:
            if finding.id not in rule_map:
                rule = self._build_rule(finding)
                rule_map[finding.id] = rule
                rules.append(rule)
            else:
                # Merge: promote to the highest severity seen, collect all
                # tags, and keep the most descriptive fullDescription.
                existing = rule_map[finding.id]
                self._merge_rule(existing, finding)
            results.append(self._build_result(finding))

        return {
            "tool": {
                "driver": {
                    "name": "escapewatch",
                    "version": __version__,
                    "informationUri": "https://github.com/escapewatch/escapewatch",
                    "rules": rules,
                },
            },
            "results": results,
            "invocations": [
                {
                    "executionSuccessful": True,
                    "properties": {
                        "environment": result.environment.to_dict(),
                        "summary": {
                            "totalScore": result.total_score,
                            "grade": result.grade,
                            "findingCount": len(result.findings),
                        },
                    },
                }
            ],
        }

    # Severity ordering for _merge_rule promotion.
    _SEV_ORDER = ["error", "warning", "note", "none"]

    def _merge_rule(self, existing: dict, finding: Finding) -> None:
        """Merge a duplicate finding ID into an existing SARIF rule.

        - Promotes defaultConfiguration.level to the highest severity seen.
        - Picks the longer fullDescription (more informative).
        - Merges tags.
        """
        new_level = finding.severity.sarif_level
        old_level = existing["defaultConfiguration"]["level"]
        if self._SEV_ORDER.index(new_level) < self._SEV_ORDER.index(old_level):
            existing["defaultConfiguration"]["level"] = new_level
            existing["properties"]["severity"] = finding.severity.value

        new_desc = finding.why_it_matters
        if len(new_desc) > len(existing["fullDescription"]["text"]):
            existing["fullDescription"]["text"] = new_desc

        # Merge category tags.
        cat_tag = finding.category.value
        if cat_tag not in existing["properties"]["tags"]:
            existing["properties"]["tags"].append(cat_tag)

    def _build_rule(self, finding: Finding) -> dict:
        rule: dict = {
            "id": finding.id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.why_it_matters},
            "helpUri": finding.references[0] if finding.references else "",
            "help": {
                "text": finding.remediation,
                "markdown": f"**Remediation:** {finding.remediation}",
            },
            "defaultConfiguration": {
                "level": finding.severity.sarif_level,
            },
            "properties": {
                "tags": [finding.category.value],
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
            },
        }
        return rule

    def _build_result(self, finding: Finding) -> dict:
        return {
            "ruleId": finding.id,
            "level": finding.severity.sarif_level,
            "message": {
                "text": f"{finding.title}: {finding.evidence}",
            },
            "properties": {
                "title": finding.title,
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
                "category": finding.category.value,
                "weightedScore": finding.weighted_score,
                "remediation": finding.remediation,
            },
        }
