from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Label:
    category: str
    label: str
    confidence: float
    evidence: tuple[str, ...] = ()
    rule_ids: tuple[str, ...] = ()
    description: str | None = None

    @property
    def value(self) -> str:
        """Return the label as a MISP machine tag."""
        return f'ptrclassify:{self.category}="{self.label}"'

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["value"] = self.value
        out["evidence"] = list(self.evidence)
        out["rule_ids"] = list(self.rule_ids)
        return out


@dataclass(frozen=True)
class LocationCandidate:
    """A possible geographic location decoded from an operator naming convention."""

    code: str
    confidence: float
    evidence: str
    rule_id: str
    city: str | None = None
    region: str | None = None
    country: str | None = None
    description: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Classification:
    input: str
    hostname: str | None
    address: str | None = None
    record_type: str | None = None
    labels: list[Label] = field(default_factory=list)
    locations: list[LocationCandidate] = field(default_factory=list)
    hints: dict[str, Any] = field(default_factory=dict)

    def values(self) -> list[str]:
        return [label.value for label in self.labels]

    def to_dict(self) -> dict[str, Any]:
        return {
            "input": self.input,
            "hostname": self.hostname,
            "address": self.address,
            "record_type": self.record_type,
            "labels": [label.to_dict() for label in self.labels],
            "locations": [location.to_dict() for location in self.locations],
            "hints": self.hints,
        }
