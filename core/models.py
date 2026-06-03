from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


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
        return {
            "stage_name": self.stage_name,
            "stage_index": self.stage_index,
            "timestamp": self.timestamp,
            "subdomains": [
                {"domain": s.domain, "source": s.source, "ip_list": s.ip_list, "is_alive": s.is_alive}
                for s in self.subdomains
            ],
            "ports": [
                {"ip": p.ip, "port": p.port, "protocol": p.protocol, "service": p.service,
                 "product": p.product, "version": p.version}
                for p in self.ports
            ],
            "fingerprints": [
                {"url": f.url, "technologies": f.technologies, "os": f.os, "server": f.server,
                 "status_code": f.status_code, "title": f.title}
                for f in self.fingerprints
            ],
            "sensitive_paths": [
                {"url": s.url, "status_code": s.status_code, "content_length": s.content_length,
                 "path_type": s.path_type}
                for s in self.sensitive_paths
            ],
            "vulnerabilities": [
                {"template_id": v.template_id, "name": v.name, "severity": v.severity,
                 "url": v.url, "matched_at": v.matched_at, "type": v.type, "description": v.description}
                for v in self.vulnerabilities
            ],
            "credential_leaks": [
                {"source": c.source, "repo": c.repo, "file": c.file, "rule": c.rule,
                 "secret_type": c.secret_type}
                for c in self.credential_leaks
            ],
            "raw_data": self.raw_data,
            "errors": self.errors,
        }


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
        self.all_subdomains.extend(result.subdomains)
        self.all_ports.extend(result.ports)
        self.all_fingerprints.extend(result.fingerprints)
        self.all_sensitive_paths.extend(result.sensitive_paths)
        self.all_vulnerabilities.extend(result.vulnerabilities)
        self.all_credential_leaks.extend(result.credential_leaks)

    def deduplicate_subdomains(self):
        seen: set[str] = set()
        unique: list[Subdomain] = []
        for s in self.all_subdomains:
            if s.domain not in seen:
                seen.add(s.domain)
                unique.append(s)
        self.all_subdomains = unique

    def to_final_report(self) -> dict:
        return {
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
            "ai_analysis": self.ai_analysis,
            "stages": [r.to_dict() for r in self.results],
            "subdomains": [
                {"domain": s.domain, "source": s.source, "ip_list": s.ip_list, "is_alive": s.is_alive}
                for s in self.all_subdomains
            ],
            "ports": [
                {"ip": p.ip, "port": p.port, "protocol": p.protocol, "service": p.service,
                 "product": p.product, "version": p.version}
                for p in self.all_ports
            ],
            "fingerprints": [
                {"url": f.url, "technologies": f.technologies, "os": f.os, "server": f.server,
                 "status_code": f.status_code, "title": f.title}
                for f in self.all_fingerprints
            ],
            "sensitive_paths": [
                {"url": s.url, "status_code": s.status_code, "content_length": s.content_length,
                 "path_type": s.path_type}
                for s in self.all_sensitive_paths
            ],
            "vulnerabilities": [
                {"template_id": v.template_id, "name": v.name, "severity": v.severity,
                 "url": v.url, "matched_at": v.matched_at, "type": v.type, "description": v.description}
                for v in self.all_vulnerabilities
            ],
            "credential_leaks": [
                {"source": c.source, "repo": c.repo, "file": c.file, "rule": c.rule,
                 "secret_type": c.secret_type}
                for c in self.all_credential_leaks
            ],
        }

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
