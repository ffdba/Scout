from __future__ import annotations

import hashlib
import ipaddress
from typing import Any
from urllib.parse import urlsplit, urlunsplit


SEVERITY_SCORES = {"critical": 90, "high": 75, "medium": 50, "low": 25, "info": 5}
REVIEW_PORTS = {23, 2375, 3306, 3389, 5432, 6379, 9200, 27017}
REVIEW_PATHS = {"backup", "config", "sensitive_file", "database", "env"}
PATH_ALIASES = {
    "备份文件": "backup", "配置文件": "config", "环境配置": "env",
    "数据库文件": "database", "Git泄露": "sensitive_file",
}
STAGE_NAMES = {1: "OSINT", 2: "Boundary", 3: "Fingerprint", 4: "Content", 5: "Validation"}


def stable_id(kind: str, *parts: Any) -> str:
    payload = "\0".join(str(part) for part in (kind, *parts))
    return f"{kind}-{hashlib.sha256(payload.encode()).hexdigest()[:16]}"


def canonical_host(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    try:
        return ipaddress.ip_address(value.strip("[]")).compressed
    except ValueError:
        return value.encode("idna").decode("ascii")


def canonical_url(value: str) -> str:
    value = value.strip()
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return value
        host = canonical_host(parsed.hostname)
        if ":" in host:
            host = f"[{host}]"
        port = parsed.port
        if port and (parsed.scheme, port) not in {("http", 80), ("https", 443)}:
            host += f":{port}"
        return urlunsplit((parsed.scheme, host, parsed.path or "/", parsed.query, ""))
    except ValueError:
        return value


def endpoint_host(value: str) -> str:
    try:
        return canonical_host(ipaddress.ip_address(value.strip("[]")).compressed)
    except ValueError:
        try:
            parsed = urlsplit(value if "://" in value else f"//{value}")
            return canonical_host(parsed.hostname or "")
        except ValueError:
            return ""


def observation_key(collection: str, row: dict) -> tuple:
    if collection == "subdomains":
        return (canonical_host(row.get("domain", "")),)
    if collection == "ports":
        return (canonical_host(row.get("ip", "")), row.get("port", 0), row.get("protocol", "tcp"))
    if collection in {"fingerprints", "sensitive_paths"}:
        return (canonical_url(row.get("url", "")),)
    if collection == "vulnerabilities":
        return (
            row.get("template_id") or row.get("name", ""),
            canonical_url(row.get("matched_at") or row.get("url", "")),
            row.get("type", ""),
        )
    return (row.get("repo", ""), row.get("file", ""), row.get("rule", ""), row.get("secret_type", ""))


def risk_level(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 75:
        return "high"
    if score >= 50:
        return "medium"
    if score > 0:
        return "low"
    return "unrated"


def build_intelligence(report: dict) -> dict:
    """Derive a local, reproducible triage view; no network or model calls."""
    assets: dict[str, dict] = {}
    findings: dict[str, dict] = {}
    nodes: dict[str, dict] = {}
    edges: dict[tuple, dict] = {}
    provenance: dict[tuple, list[dict]] = {}

    for index, stage in enumerate(report.get("stages", [])):
        for collection in ("subdomains", "ports", "fingerprints", "sensitive_paths",
                           "vulnerabilities", "credential_leaks"):
            for row_index, row in enumerate(stage.get(collection, [])):
                key = (collection, observation_key(collection, row))
                provenance.setdefault(key, []).append({
                    "ref": f"#/stages/{index}/{collection}/{row_index}",
                    "stage": stage.get("stage_index", 0),
                    "source": row.get("source") or stage.get("stage_name", ""),
                })

    def evidence(collection: str, row: dict, index: int) -> list[dict]:
        return provenance.get((collection, observation_key(collection, row)), [{
            "ref": f"#/{collection}/{index}", "stage": 0,
            "source": row.get("source") or collection,
        }])

    def node(node_id: str, kind: str, label: str):
        nodes[node_id] = {"id": node_id, "kind": kind, "label": label}

    def link(source: str, target: str, relation: str):
        edges[(source, target, relation)] = {
            "source": source, "target": target, "relation": relation,
        }

    def asset(host: str) -> dict:
        host = canonical_host(host)
        if host not in assets:
            asset_id = stable_id("asset", host)
            try:
                ipaddress.ip_address(host)
                kind = "ip"
            except ValueError:
                kind = "domain"
            assets[host] = {
                "id": asset_id, "host": host, "kind": kind,
                "ips": set(), "urls": set(), "technologies": set(),
                "services": {}, "finding_ids": set(), "evidence": [],
            }
            node(asset_id, kind, host)
        return assets[host]

    def endpoint(url: str) -> dict | None:
        host = endpoint_host(url)
        if not host:
            return None
        item = asset(host)
        url = canonical_url(url)
        item["urls"].add(url)
        url_id = stable_id("url", url)
        node(url_id, "url", url)
        link(item["id"], url_id, "has_endpoint")
        return item

    def add_finding(item: dict | None, finding: dict):
        finding_id = finding["id"]
        if finding_id in findings:
            current = findings[finding_id]
            current["evidence"].extend(e for e in finding["evidence"] if e not in current["evidence"])
            if finding["score"] > current["score"]:
                current.update({k: finding[k] for k in ("score", "severity")})
        else:
            findings[finding_id] = finding
            node(finding_id, "finding", finding["title"])
        if item:
            item["finding_ids"].add(finding_id)
            link(item["id"], finding_id, "has_finding")

    for index, row in enumerate(report.get("subdomains", [])):
        host = row.get("domain", "")
        if not host:
            continue
        item = asset(host)
        item["evidence"].extend(evidence("subdomains", row, index))
        for ip in row.get("ip_list", []):
            address = asset(ip)
            item["ips"].add(address["host"])
            link(item["id"], address["id"], "observed_resolves_to")

    for index, row in enumerate(report.get("ports", [])):
        if not row.get("ip") or not row.get("port"):
            continue
        item = asset(row["ip"])
        service_id = stable_id("service", *observation_key("ports", row))
        service = {
            "port": row["port"], "protocol": row.get("protocol", "tcp"),
            "service": row.get("service", ""), "product": row.get("product", ""),
            "version": row.get("version", ""),
        }
        item["services"][service_id] = service
        refs = evidence("ports", row, index)
        item["evidence"].extend(refs)
        location = f"{item['host']}:{service['port']}/{service['protocol']}"
        node(service_id, "service", location)
        link(item["id"], service_id, "exposes")
        if service["port"] in REVIEW_PORTS:
            add_finding(item, {
                "id": stable_id("exposure", service_id), "kind": "service_exposure",
                "title": f"Review exposed service on port {service['port']}",
                "severity": "unrated", "score": 25, "status": "needs_review",
                "location": location, "evidence": refs,
                "reason": "An open port is observed; authentication and reachability context are unknown.",
                "recommendation": "Confirm intended exposure, access restrictions and authentication.",
            })

    for index, row in enumerate(report.get("fingerprints", [])):
        item = endpoint(row.get("url", ""))
        if item:
            for tech in row.get("technologies", []):
                name = tech.get("name", "") if isinstance(tech, dict) else str(tech)
                if name:
                    item["technologies"].add(name)
            item["evidence"].extend(evidence("fingerprints", row, index))

    for index, row in enumerate(report.get("sensitive_paths", [])):
        item = endpoint(row.get("url", ""))
        path_type = row.get("path_type", "").lower()
        path_type = PATH_ALIASES.get(path_type, path_type)
        if path_type not in REVIEW_PATHS or not item:
            continue
        status = row.get("status_code", 0)
        # A successful HTTP response is a lead, not proof of a leaked file.
        if status != 200:
            continue
        location = canonical_url(row["url"])
        add_finding(item, {
            "id": stable_id("path", location), "kind": "sensitive_path",
            "title": f"Review accessible {path_type} path",
            "severity": "unrated", "score": 30, "status": "needs_review",
            "location": location, "evidence": evidence("sensitive_paths", row, index),
            "reason": "HTTP 200 on a classified path; contents and soft-404 behavior are unverified.",
            "recommendation": "Verify content type and false-positive controls before reporting exposure.",
        })

    for index, row in enumerate(report.get("vulnerabilities", [])):
        location = canonical_url(row.get("matched_at") or row.get("url", ""))
        item = endpoint(location or row.get("url", ""))
        severity = row.get("severity", "").lower() or "unknown"
        add_finding(item, {
            "id": stable_id("vuln", *observation_key("vulnerabilities", row)),
            "kind": "template_match", "template_id": row.get("template_id", ""),
            "title": row.get("name") or row.get("template_id") or "Unnamed template match",
            "severity": severity, "score": SEVERITY_SCORES.get(severity, 0),
            "status": "tool_reported", "location": location,
            "evidence": evidence("vulnerabilities", row, index),
            "references": row.get("reference", []),
            "reason": "A scanner template matched. Exploitability has not been independently verified.",
            "recommendation": "Review the template evidence, reproduce within scope, then prioritize remediation.",
        })

    for index, row in enumerate(report.get("credential_leaks", [])):
        location = f"{row.get('repo', '')}:{row.get('file', '')}"
        add_finding(None, {
            "id": stable_id("leak", *observation_key("credential_leaks", row)),
            "kind": "credential_leak", "title": row.get("rule") or "Potential credential in repository",
            "severity": "unrated", "score": 60, "status": "needs_review",
            "location": location, "evidence": evidence("credential_leaks", row, index),
            "reason": "A secret-detection rule matched; validity and asset ownership are unverified.",
            "recommendation": "Review privately, rotate valid credentials and remove them from history.",
        })

    ranked_findings = sorted(findings.values(), key=lambda f: (-f["score"], f["id"]))
    ranked_assets = []
    for item in assets.values():
        signals = [findings[key] for key in item["finding_ids"]]
        base = max((f["score"] for f in signals), default=0)
        kinds = {f["kind"] for f in signals}
        # Corroborating observations add priority, never independent vulnerability severity.
        bonus = min(10, max(0, len(kinds) - 1) * 5) if base else 0
        score = min(100, base + bonus)
        ranked_assets.append({
            **item, "ips": sorted(item["ips"]), "urls": sorted(item["urls"]),
            "technologies": sorted(item["technologies"]),
            "services": sorted(item["services"].values(), key=lambda s: (s["port"], s["protocol"])),
            "finding_ids": sorted(item["finding_ids"]),
            "evidence": list({e["ref"]: e for e in item["evidence"]}.values()),
            "risk_score": score, "risk_level": risk_level(score),
            "score_breakdown": {"strongest_signal": base, "corroboration_bonus": bonus},
            "reasons": [f["title"] for f in sorted(signals, key=lambda f: (-f["score"], f["id"]))],
        })
    ranked_assets.sort(key=lambda a: (-a["risk_score"], a["host"]))

    coverage = []
    warnings = []
    for stage_id, name in STAGE_NAMES.items():
        records = [s for s in report.get("stages", []) if s.get("stage_index") == stage_id]
        errors = [error for s in records for error in s.get("errors", [])]
        status = "not_recorded" if not records else "partial" if errors else "recorded"
        coverage.append({"stage": stage_id, "name": name, "status": status, "errors": errors})
        if status != "recorded":
            warnings.append(f"{name}: {status}; absence of findings does not establish a clean result.")

    return {
        "version": "1.0", "scoring": "heuristic-priority-v1",
        "scoring_note": "0-100 triage priority, not CVSS or confirmed exploitability. No shared-IP risk inheritance.",
        "assets": ranked_assets, "findings": ranked_findings,
        "graph": {
            "nodes": sorted(nodes.values(), key=lambda n: n["id"]),
            "edges": [edges[key] for key in sorted(edges)],
        },
        "coverage": coverage,
        "warnings": warnings + ["Recorded stages do not guarantee every tool succeeded; per-tool coverage is not available."],
        "summary": {
            "total_assets": len(ranked_assets), "total_findings": len(ranked_findings),
            "tool_reported": sum(f["status"] == "tool_reported" for f in ranked_findings),
            "needs_review": sum(f["status"] == "needs_review" for f in ranked_findings),
            "highest_priority_score": max(
                [f["score"] for f in ranked_findings] + [a["risk_score"] for a in ranked_assets],
                default=0,
            ),
        },
    }


def compare_reports(current: dict, baseline: dict) -> dict:
    if canonical_host(current.get("target", "")) != canonical_host(baseline.get("target", "")):
        raise ValueError("Baseline target must match the current report target.")
    # Rebuild from observations rather than trusting stale derived fields.
    current_view = build_intelligence(current)
    baseline_view = build_intelligence(baseline)

    def changes(collection: str) -> dict:
        before = {row["id"]: row for row in baseline_view[collection]}
        after = {row["id"]: row for row in current_view[collection]}
        fields = (
            ("risk_score", "urls", "ips", "technologies", "services", "finding_ids")
            if collection == "assets" else ("severity", "score", "status")
        )
        changed = []
        for key in sorted(before.keys() & after.keys()):
            delta = {field: {"before": before[key].get(field), "after": after[key].get(field)}
                     for field in fields if before[key].get(field) != after[key].get(field)}
            if delta:
                changed.append({"id": key, "changes": delta})
        return {
            "new": [after[key] for key in sorted(after.keys() - before.keys())],
            "persistent": [after[key] for key in sorted(after.keys() & before.keys())],
            "not_observed": [before[key] for key in sorted(before.keys() - after.keys())],
            "changed": changed,
        }

    return {
        "baseline_generated_at": baseline.get("generated_at", ""),
        "current_generated_at": current.get("generated_at", ""),
        "note": "Not observed does not mean resolved; compare scope and tool coverage before closing findings.",
        "assets": changes("assets"), "findings": changes("findings"),
    }
