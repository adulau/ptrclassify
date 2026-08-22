from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from importlib import import_module
from importlib.resources import files
import ipaddress
import json
import re
from typing import Iterable

from .models import Classification, Label, LocationCandidate
from .parser import PTRRecord, parse_ptr_record
from .taxonomy import TAXONOMY


@dataclass(frozen=True)
class _CompiledRule:
    id: str
    category: str
    label: str
    confidence: float
    regexes: tuple[re.Pattern[str], ...]
    patterns: tuple[str, ...]
    description: str | None = None


@dataclass(frozen=True)
class _CompiledLocationRule:
    id: str
    confidence: float
    regex: re.Pattern[str]
    locations: dict[str, dict[str, str]]
    description: str | None = None


class PTRClassifier:
    """Explainable heuristic classifier for PTR hostnames.

    The classifier is deliberately multi-label: allocation, access medium,
    infrastructure role, hosting role, organization context, etc. can all be
    true at once.
    """

    def __init__(
        self,
        extra_rules: Iterable[dict] | None = None,
        engine: str = "re",
        extra_location_rules: Iterable[dict] | None = None,
    ):
        """Create a classifier using the standard or Hyperscan regexp engine.

        ``engine="hyperscan"`` requires the optional ``hyperscan`` package.  It
        compiles every rule pattern into one database, which avoids performing
        hundreds of individual regexp searches for each hostname.
        """
        if engine not in {"re", "hyperscan"}:
            raise ValueError("engine must be 're' or 'hyperscan'")
        raw_rules = json.loads(files("ptrclassify.data").joinpath("rules.json").read_text())
        if extra_rules:
            raw_rules.extend(extra_rules)
        self.rules = tuple(self._compile_rule(rule) for rule in raw_rules)
        raw_location_rules = json.loads(
            files("ptrclassify.data").joinpath("location_rules.json").read_text()
        )
        if extra_location_rules:
            raw_location_rules.extend(extra_location_rules)
        self.location_rules = tuple(
            self._compile_location_rule(rule) for rule in raw_location_rules
        )
        self.engine = engine
        self._hyperscan = self._compile_hyperscan() if engine == "hyperscan" else None

    @staticmethod
    def _compile_rule(rule: dict) -> _CompiledRule:
        return _CompiledRule(
            id=rule["id"],
            category=rule["category"],
            label=rule["label"],
            confidence=float(rule.get("confidence", 0.8)),
            regexes=tuple(re.compile(pattern, re.IGNORECASE) for pattern in rule["patterns"]),
            patterns=tuple(rule["patterns"]),
            description=rule.get("description"),
        )

    @staticmethod
    def _compile_location_rule(rule: dict) -> _CompiledLocationRule:
        return _CompiledLocationRule(
            id=rule["id"],
            confidence=float(rule.get("confidence", 0.8)),
            regex=re.compile(rule["pattern"], re.IGNORECASE),
            locations={key.lower(): value for key, value in rule["locations"].items()},
            description=rule.get("description"),
        )

    def _compile_hyperscan(self):
        try:
            hyperscan = import_module("hyperscan")
        except ImportError as exc:
            raise RuntimeError(
                "Hyperscan support is not installed; install ptrclassify[hyperscan]"
            ) from exc

        expressions = []
        ids = []
        flags = []
        pattern_map = []
        for rule_index, rule in enumerate(self.rules):
            for pattern_index, pattern in enumerate(rule.patterns):
                expressions.append(pattern.encode())
                ids.append(len(pattern_map))
                flags.append(hyperscan.HS_FLAG_CASELESS | hyperscan.HS_FLAG_SOM_LEFTMOST)
                pattern_map.append((rule_index, pattern_index))
        database = hyperscan.Database()
        database.compile(expressions=expressions, ids=ids, flags=flags)
        return database, tuple(pattern_map)

    def classify(self, value: str | PTRRecord) -> Classification:
        record = parse_ptr_record(value) if isinstance(value, str) else value
        result = Classification(
            input=record.raw,
            hostname=record.hostname,
            address=record.address,
            record_type=record.record_type,
        )

        if record.record_type == "CNAME":
            result.labels.append(
                Label("dns", "cname", 1.0, evidence=("CNAME",), rule_ids=("dns.cname",), description=TAXONOMY["dns"]["cname"])
            )
            return result

        hostname = (record.hostname or "").lower().rstrip(".")
        if not hostname:
            return result

        matched: dict[tuple[str, str], dict] = defaultdict(
            lambda: {"confidence": 0.0, "evidence": [], "rule_ids": [], "description": None}
        )

        for rule, evidence in self._matches(hostname):
            key = (rule.category, rule.label)
            slot = matched[key]
            slot["confidence"] = max(slot["confidence"], rule.confidence)
            if evidence not in slot["evidence"]:
                slot["evidence"].append(evidence)
            if rule.id not in slot["rule_ids"]:
                slot["rule_ids"].append(rule.id)
            slot["description"] = rule.description or TAXONOMY.get(rule.category, {}).get(rule.label)

        self._add_ip_encoded_hint(record, hostname, matched, result)
        self._extract_cloud_hints(hostname, result)
        self._extract_location_candidates(hostname, result)
        self._add_generic_reverse_hint(hostname, matched)

        result.labels = [
            Label(
                category=category,
                label=label,
                confidence=round(data["confidence"], 3),
                evidence=tuple(data["evidence"]),
                rule_ids=tuple(data["rule_ids"]),
                description=data["description"],
            )
            for (category, label), data in matched.items()
        ]
        result.labels.sort(key=lambda x: (-x.confidence, x.category, x.label))
        self._add_conflict_hints(result)
        return result

    def _extract_location_candidates(
        self, hostname: str, result: Classification
    ) -> None:
        """Apply operator-scoped templates and resolve only curated location codes."""
        seen: set[tuple[str, str]] = set()
        for rule in self.location_rules:
            match = rule.regex.search(hostname)
            if not match:
                continue
            code = match.group("code").lower()
            location = rule.locations.get(code)
            if location is None or (rule.id, code) in seen:
                continue
            seen.add((rule.id, code))
            result.locations.append(
                LocationCandidate(
                    code=code,
                    confidence=rule.confidence,
                    evidence=match.group(0),
                    rule_id=rule.id,
                    city=location.get("city"),
                    region=location.get("region"),
                    country=location.get("country"),
                    description=rule.description,
                )
            )
        result.locations.sort(key=lambda item: (-item.confidence, item.rule_id, item.code))

    def _matches(self, hostname: str):
        if self._hyperscan is None:
            for rule in self.rules:
                for regex in rule.regexes:
                    match = regex.search(hostname)
                    if match:
                        yield rule, match.group(0)
                        break
            return

        database, pattern_map = self._hyperscan
        subject = hostname.encode()
        matches: dict[int, tuple[int, int, int]] = {}

        def on_match(pattern_id, start, end, _flags, _context):
            rule_index, pattern_index = pattern_map[pattern_id]
            previous = matches.get(rule_index)
            candidate = (pattern_index, start, end)
            if (
                previous is None
                or pattern_index < previous[0]
                or (
                    pattern_index == previous[0]
                    and (start < previous[1] or (start == previous[1] and end > previous[2]))
                )
            ):
                matches[rule_index] = candidate

        database.scan(subject, match_event_handler=on_match)
        for rule_index in sorted(matches):
            _pattern_index, start, end = matches[rule_index]
            yield self.rules[rule_index], subject[start:end].decode(errors="replace")

    @staticmethod
    def _add_conflict_hints(result: Classification) -> None:
        values = {(label.category, label.label) for label in result.labels}
        conflicts = []
        if {("allocation", "dynamic"), ("allocation", "static")} <= values:
            conflicts.append("allocation:dynamic vs allocation:static")
        if conflicts:
            result.hints["conflicts"] = conflicts

    @staticmethod
    def _add_ip_encoded_hint(record: PTRRecord, hostname: str, matched: dict, result: Classification) -> None:
        if not record.address:
            return
        ip = ipaddress.ip_address(record.address)
        if ip.version != 4:
            return
        octets = record.address.split(".")
        variants = {
            record.address,
            "-".join(octets),
            "_".join(octets),
            "x".join(octets),
            "".join(f"{int(x):03d}" for x in octets),
        }
        if any(v.lower() in hostname for v in variants):
            key = ("naming", "ip-encoded")
            matched[key] = {
                "confidence": 0.99,
                "evidence": [record.address],
                "rule_ids": ["naming.ip-encoded"],
                "description": TAXONOMY["naming"]["ip-encoded"],
            }
            result.hints["embedded_ip"] = record.address

    @staticmethod
    def _extract_cloud_hints(hostname: str, result: Classification) -> None:
        aws = re.search(r"\.([a-z]{2}(?:-gov)?-[a-z]+-\d)\.compute\.amazonaws\.com$", hostname)
        if aws:
            result.hints["cloud_region"] = aws.group(1)
        elif hostname.endswith(".compute-1.amazonaws.com"):
            result.hints["cloud_region"] = "us-east-1 (legacy compute-1 naming)"

    @staticmethod
    def _add_generic_reverse_hint(hostname: str, matched: dict) -> None:
        # Conservative: call it generic only if the first label is mostly numbers/IP punctuation
        # and no strong service role was already inferred.
        first = hostname.split(".", 1)[0]
        digit_ratio = sum(c.isdigit() for c in first) / max(1, len(first))
        if digit_ratio < 0.35:
            return
        semantic_categories = {category for category, _ in matched}
        if "hosting" in semantic_categories or "role" in semantic_categories:
            return
        key = ("naming", "generic-reverse")
        matched[key] = {
            "confidence": 0.70,
            "evidence": [first],
            "rule_ids": ["naming.generic-reverse"],
            "description": TAXONOMY["naming"]["generic-reverse"],
        }


def classify(value: str) -> list[Label]:
    """Convenience API matching the requested 'PTR -> list of labels' shape."""
    return PTRClassifier().classify(value).labels
