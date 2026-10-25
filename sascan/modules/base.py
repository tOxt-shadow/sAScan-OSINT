"""Shared result container for scan modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sascan.models import Finding


@dataclass(slots=True)
class ModuleResult:
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def merge(self, other: "ModuleResult") -> None:
        self.findings.extend(other.findings)
        self.errors.extend(other.errors)
        self.notes.extend(other.notes)
        for key, value in other.metadata.items():
            if key in self.metadata and isinstance(self.metadata[key], list):
                self.metadata[key].extend(value if isinstance(value, list) else [value])
            else:
                self.metadata[key] = value
