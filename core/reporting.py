from __future__ import annotations

import json
import re
from pathlib import Path

from core.intelligence import build_intelligence, compare_reports


COLLECTION_FIELDS = {
    "subdomains": ("domain", "source"),
    "ports": ("ip", "protocol", "service", "product", "version"),
    "fingerprints": ("url", "os", "server", "title"),
    "sensitive_paths": ("url", "path_type"),
    "vulnerabilities": ("template_id", "name", "severity", "url", "matched_at", "type", "description"),
    "credential_leaks": ("source", "repo", "file", "rule", "secret_type"),
}


def _validate_collections(report: dict):
    for collection, string_fields in COLLECTION_FIELDS.items():
        rows = report.get(collection, [])
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError(f"Report field {collection!r} must be a list of objects.")
        for row in rows:
            for field in string_fields:
                if field in row and not isinstance(row[field], str):
                    raise ValueError(f"{collection}.{field} must be a string.")
            for field in ("port", "status_code", "content_length"):
                if field in row and (type(row[field]) is not int or row[field] < 0):
                    raise ValueError(f"{collection}.{field} must be a non-negative integer.")
            for field in ("ip_list", "reference"):
                if field in row and (
                    not isinstance(row[field], list) or any(not isinstance(v, str) for v in row[field])
                ):
                    raise ValueError(f"{collection}.{field} must be a list of strings.")
            if "technologies" in row:
                techs = row["technologies"]
                if not isinstance(techs, list) or any(
                    not isinstance(t, (str, dict)) or (
                        isinstance(t, dict) and not isinstance(t.get("name", ""), str)
                    ) for t in techs
                ):
                    raise ValueError("fingerprints.technologies must contain names or technology objects.")


def load_report(path: str | Path) -> dict:
    path = Path(path)
    with path.open(encoding="utf-8-sig") as stream:
        if path.suffix.lower() == ".jsonl":
            report = None
            for line in stream:
                if line.strip():
                    report = json.loads(line)
            if report is None:
                raise ValueError("Report file is empty.")
        else:
            report = json.load(stream)
    if not isinstance(report, dict) or not isinstance(report.get("target"), str) or not report["target"].strip():
        raise ValueError("Expected a Scout report object with a non-empty target.")
    _validate_collections(report)
    stages = report.get("stages", [])
    if not isinstance(stages, list) or any(not isinstance(stage, dict) for stage in stages):
        raise ValueError("stages must be a list of objects.")
    for stage in stages:
        if "stage_index" in stage and type(stage["stage_index"]) is not int:
            raise ValueError("stage_index must be an integer.")
        errors = stage.get("errors", [])
        if not isinstance(errors, list) or any(not isinstance(error, str) for error in errors):
            raise ValueError("Stage errors must be a list of strings.")
        _validate_collections(stage)
    return report


def _text(value) -> str:
    text = re.sub(r"\s+", " ", str(value))
    return re.sub(r"([\\`*_{}\[\]()<>|#!])", r"\\\1", text)


def _change_text(field: str, value) -> str:
    if field == "services":
        return ", ".join(f"{s['port']}/{s['protocol']}" for s in value) or "none"
    if isinstance(value, list):
        if field in {"urls", "finding_ids"}:
            return str(len(value))
        return ", ".join(str(item) for item in value) or "none"
    return str(value)


def render_markdown(report: dict) -> str:
    view = report["intelligence"]
    summary = view["summary"]
    lines = [
        f"# Scout Assessment: {_text(report['target'])}", "",
        f"Generated: {_text(report.get('generated_at', ''))}", "",
    ]
    if report.get("demo"):
        lines += ["> SYNTHETIC DEMO. No target was scanned; these are fictional observations.", ""]
    lines += [
        "## Overview", "",
        f"- Assets: {summary['total_assets']}",
        f"- Tool-reported matches: {summary['tool_reported']}",
        f"- Leads requiring review: {summary['needs_review']}",
        "", view["scoring_note"], "",
        "## Asset Priority", "",
        "| Host | Priority | Technologies | Evidence-based Reasons |",
        "| --- | --- | --- | --- |",
    ]
    for item in view["assets"]:
        lines.append(
            f"| {_text(item['host'])} | {item['risk_score']} ({item['risk_level']}) "
            f"| {_text(', '.join(item['technologies']) or '-')} "
            f"| {_text('; '.join(item['reasons']) or 'No scored signals')} |"
        )
    if not view["assets"]:
        lines += ["| No observed assets | - | - | - |"]
    lines += ["", "## Review Queue", ""]
    for index, finding in enumerate(view["findings"], start=1):
        lines += [
            f"### {index}. {_text(finding['title'])}", "",
            f"- ID: `{finding['id']}`",
            f"- Status: {finding['status']}; scanner severity: {_text(finding['severity'])}; priority: {finding['score']}",
            f"- Location: {_text(finding['location'])}",
            f"- Rationale: {_text(finding['reason'])}",
            f"- Next action: {_text(finding['recommendation'])}",
            "- Evidence: " + ", ".join(f"`{e['ref']}`" for e in finding["evidence"]),
            "",
        ]
    if not view["findings"]:
        lines += ["No scored findings were observed. This is not a clean bill of health.", ""]
    if "comparison" in report:
        comparison = report["comparison"]
        lines += ["## Baseline Comparison", "", comparison["note"], ""]
        for collection in ("assets", "findings"):
            delta = comparison[collection]
            lines += [
                f"### {collection.title()}", "",
                f"New: {len(delta['new'])}; persistent: {len(delta['persistent'])}; "
                f"not observed: {len(delta['not_observed'])}; changed: {len(delta['changed'])}.", "",
            ]
            for status in ("new", "not_observed"):
                for row in delta[status]:
                    label = row.get("title") or row.get("host", "")
                    lines.append(f"- {status}: {_text(label)} (`{row['id']}`)")
            for row in delta["changed"]:
                current = next(item for item in delta["persistent"] if item["id"] == row["id"])
                label = current.get("title") or current.get("host", "")
                details = "; ".join(
                    f"{field}: {_change_text(field, values['before'])} -> "
                    f"{_change_text(field, values['after'])}"
                    for field, values in row["changes"].items()
                )
                lines.append(f"- changed: {_text(label)}; {_text(details)} (`{row['id']}`)")
            lines.append("")
    lines += ["## Coverage And Limitations", ""]
    for stage in view["coverage"]:
        lines.append(f"- {stage['name']}: {stage['status']}")
        lines += [f"  - {_text(error)}" for error in stage["errors"]]
    lines += ["", *[f"- {_text(warning)}" for warning in view["warnings"]], ""]
    return "\n".join(lines)


def write_report(report: dict, output_dir: str | Path, *,
                 baseline: dict | None = None, fmt: str = "json") -> dict[str, Path]:
    if fmt not in {"json", "jsonl"}:
        raise ValueError("Output format must be json or jsonl.")
    report = {**report, "schema_version": "2.0", "intelligence": build_intelligence(report)}
    report.pop("comparison", None)
    if baseline is not None:
        report["comparison"] = compare_reports(report, baseline)
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^A-Za-z0-9_-]", "_", report["target"])[:120] or "scout"
    prefix = directory / slug
    paths = {
        "json": Path(f"{prefix}_report.json"),
        "markdown": Path(f"{prefix}_assessment.md"),
    }
    paths["json"].write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    paths["markdown"].write_text(render_markdown(report), encoding="utf-8")
    if fmt == "jsonl":
        paths["jsonl"] = Path(f"{prefix}_report.jsonl")
        with paths["jsonl"].open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(report, ensure_ascii=False) + "\n")
    if report.get("ai_analysis"):
        paths["ai_analysis"] = Path(f"{prefix}_ai_analysis.md")
        paths["ai_analysis"].write_text(report["ai_analysis"], encoding="utf-8")
    return paths
