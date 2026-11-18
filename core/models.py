from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime
from typing import Any

from core.intelligence import SEVERITY_SCORES, build_intelligence, observation_key


COLLECTIONS = ("subdomains", "ports", "fingerprints", "sensitive_paths",
               "vulnerabilities", "credential_leaks")


def _merge_records(collection: str, rows: list) -> list:
    merged: dict[tuple, Any] = {}
    for row in rows:
        key = observation_key(collection, asdict(row))
        if key not in merged:
            merged[key] = deepcopy(row)
            continue
        existing = merged[key]
        for attr in fields(row):
            value = getattr(row, attr.name)
            previous = getattr(existing, attr.name)
            if isinstance(value, list):
                previous.extend(deepcopy(item) for item in value if item not in previous)
            elif attr.name == "source":
                existing.source = ",".join(dict.fromkeys(
                    name for name in f"{previous},{value}".split(",") if name
                ))
            elif attr.name == "severity":
                if SEVERITY_SCORES.get(value.lower(), 0) > SEVERITY_SCORES.get(previous.lower(), 0):
                    existing.severity = value
            elif value:
                setattr(existing, attr.name, value)
    return list(merged.values())


@dataclass
class Subdomain:
    domain: str
    source: str = ""
    ip_list: list[str] = field(default_factory=list)
    is_alive: bool = False


@dataclass
class PortInfo:
    ip: str
    port: int
    protocol: str = "tcp"
    service: str = ""
    product: str = ""
    version: str = ""
    banner: str = ""


@dataclass
class Fingerprint:
    url: str
    technologies: list[dict[str, str]] = field(default_factory=list)
    os: str = ""
    server: str = ""
    status_code: int = 0
    title: str = ""
    content_length: int = 0


@dataclass
class SensitivePath:
    url: str
    status_code: int = 0
    content_length: int = 0
    path_type: str = ""
    response_snippet: str = ""


@dataclass
class Vulnerability:
    template_id: str = ""
    name: str = ""
    severity: str = ""
    url: str = ""
    matched_at: str = ""
    type: str = ""
    description: str = ""
    reference: list[str] = field(default_factory=list)
    extraction: str = ""


@dataclass
class CredentialLeak:
    source: str = ""
    repo: str = ""
    file: str = ""
    rule: str = ""
    secret_type: str = ""
    match: str = ""


@dataclass
class StageResult:
    stage_name: str = ""
    stage_index: int = 0
    timestamp: str = ""
    subdomains: list[Subdomain] = field(default_factory=list)
    ports: list[PortInfo] = field(default_factory=list)
    fingerprints: list[Fingerprint] = field(default_factory=list)
    sensitive_paths: list[SensitivePath] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    credential_leaks: list[CredentialLeak] = field(default_factory=list)
    raw_data: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> dict:
        result = asdict(self)
        # Preserve useful metadata without publishing captured secrets or response bodies.
        for collection, omitted in {
            "credential_leaks": ("match",),
            "vulnerabilities": ("extraction",),
            "sensitive_paths": ("response_snippet",),
            "ports": ("banner",),
        }.items():
            for row in result[collection]:
                for key in omitted:
                    row.pop(key, None)
        return result


@dataclass
class PipelineContext:
    target: str = ""
    results: list[StageResult] = field(default_factory=list)
    all_subdomains: list[Subdomain] = field(default_factory=list)
    all_ports: list[PortInfo] = field(default_factory=list)
    all_fingerprints: list[Fingerprint] = field(default_factory=list)
    all_sensitive_paths: list[SensitivePath] = field(default_factory=list)
    all_vulnerabilities: list[Vulnerability] = field(default_factory=list)
    all_credential_leaks: list[CredentialLeak] = field(default_factory=list)
    agent_decisions: list[dict[str, Any]] = field(default_factory=list)
    ai_analysis: str = ""

    def merge(self, result: StageResult):
        self.results.append(result)
        for collection in COLLECTIONS:
            name = f"all_{collection}"
            setattr(self, name, _merge_records(
                collection, getattr(self, name) + getattr(result, collection)
            ))

    def deduplicate_subdomains(self):
        self.all_subdomains = _merge_records("subdomains", self.all_subdomains)

    def to_final_report(self) -> dict:
        snapshot = StageResult(**{name: getattr(self, f"all_{name}") for name in COLLECTIONS}).to_dict()
        report = {
            "schema_version": "2.0",
            "target": self.target,
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_subdomains": len(self.all_subdomains),
                "total_open_ports": len(self.all_ports),
                "total_fingerprints": len(self.all_fingerprints),
                "total_sensitive_paths": len(self.all_sensitive_paths),
                "total_vulnerabilities": len(self.all_vulnerabilities),
                "total_credential_leaks": len(self.all_credential_leaks),
                "vulnerability_by_severity": self._severity_summary(),
            },
            "agent_decisions": self.agent_decisions,
            "agent_thoughts": [
                {"stage": result.stage_index, **thought}
                for result in self.results
                for thought in result.raw_data.get("agent_thoughts", [])
            ],
            "ai_analysis": self.ai_analysis,
            "stages": [r.to_dict() for r in self.results],
            **{name: snapshot[name] for name in COLLECTIONS},
        }
        report["intelligence"] = build_intelligence(report)
        return report

    def _severity_summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for v in self.all_vulnerabilities:
            counts[v.severity] = counts.get(v.severity, 0) + 1
        return counts

    def save_jsonl(self, path: str):
        report = self.to_final_report()
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(report, ensure_ascii=False) + "\n")

    def save_json(self, path: str):
        report = self.to_final_report()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
