from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from core.intelligence import build_intelligence, canonical_url, compare_reports
from core.models import Fingerprint, PipelineContext, PortInfo, StageResult, Subdomain, Vulnerability
from core.reporting import load_report

ROOT = Path(__file__).resolve().parents[1]


class IntelligenceTests(unittest.TestCase):
    def setUp(self):
        self.report = load_report(ROOT / "examples" / "demo_report.json")
        self.baseline = load_report(ROOT / "examples" / "demo_baseline.json")

    def test_demo_has_explainable_priority(self):
        view = build_intelligence(self.report)
        first = view["assets"][0]
        self.assertEqual(first["host"], "app.example.test")
        self.assertEqual(first["risk_score"], 80)
        self.assertEqual(first["score_breakdown"], {"strongest_signal": 75, "corroboration_bonus": 5})
        self.assertEqual(view["summary"]["tool_reported"], 2)
        self.assertEqual(view["summary"]["needs_review"], 2)
        self.assertEqual(view["summary"]["highest_priority_score"], 80)

    def test_shared_ip_does_not_inherit_findings(self):
        assets = {a["host"]: a for a in build_intelligence(self.report)["assets"]}
        self.assertEqual(assets["docs.example.test"]["risk_score"], 0)
        self.assertEqual(assets["docs.example.test"]["finding_ids"], [])
        self.assertEqual(assets["192.0.2.10"]["risk_score"], 25)

    def test_graph_has_no_dangling_edges(self):
        graph = build_intelligence(self.report)["graph"]
        node_ids = {n["id"] for n in graph["nodes"]}
        for edge in graph["edges"]:
            self.assertIn(edge["source"], node_ids)
            self.assertIn(edge["target"], node_ids)
        self.assertIn("observed_resolves_to", {e["relation"] for e in graph["edges"]})

    def test_403_and_unknown_content_are_not_confirmed_leaks(self):
        findings = build_intelligence(self.report)["findings"]
        paths = [f for f in findings if f["kind"] == "sensitive_path"]
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["status"], "needs_review")
        self.assertEqual(paths[0]["severity"], "unrated")
        self.assertIn("soft-404", paths[0]["reason"])

    def test_existing_chinese_path_classifications_work(self):
        self.report["sensitive_paths"][0]["path_type"] = "配置文件"
        findings = build_intelligence(self.report)["findings"]
        self.assertTrue(any(f["kind"] == "sensitive_path" for f in findings))

    def test_evidence_refs_resolve_to_actual_observations(self):
        view = build_intelligence(self.report)
        for finding in view["findings"]:
            for evidence in finding["evidence"]:
                value = self.report
                for token in evidence["ref"][2:].split("/"):
                    value = value[int(token)] if isinstance(value, list) else value[token]
                self.assertIsInstance(value, dict)

    def test_partial_coverage_is_visible(self):
        view = build_intelligence(self.report)
        stage = next(s for s in view["coverage"] if s["stage"] == 4)
        self.assertEqual(stage["status"], "partial")
        self.assertIn("incomplete", stage["errors"][0])
        self.assertTrue(view["warnings"])

    def test_empty_report_is_not_a_clean_result(self):
        view = build_intelligence({"target": "example.test"})
        self.assertEqual(view["summary"]["total_findings"], 0)
        self.assertEqual(view["assets"], [])
        self.assertTrue(all(s["status"] == "not_recorded" for s in view["coverage"]))

    def test_deterministic_without_mutating_input(self):
        before = copy.deepcopy(self.report)
        first = build_intelligence(self.report)
        self.assertEqual(first, build_intelligence(self.report))
        self.assertEqual(before, self.report)
        json.dumps(first)

    def test_duplicate_matches_keep_one_id_and_highest_severity(self):
        duplicate = copy.deepcopy(self.report["vulnerabilities"][0])
        duplicate["severity"] = "low"
        self.report["vulnerabilities"].append(duplicate)
        view = build_intelligence(self.report)
        matches = [f for f in view["findings"] if f.get("template_id") == duplicate["template_id"]]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["severity"], "high")

    def test_baseline_tracks_changes_without_claiming_resolution(self):
        delta = compare_reports(self.report, self.baseline)
        self.assertEqual(len(delta["assets"]["new"]), 2)
        self.assertEqual(len(delta["assets"]["not_observed"]), 1)
        self.assertEqual(len(delta["findings"]["new"]), 3)
        self.assertEqual(len(delta["findings"]["persistent"]), 1)
        self.assertEqual(len(delta["findings"]["not_observed"]), 1)
        self.assertEqual(delta["findings"]["changed"][0]["changes"]["severity"],
                         {"before": "medium", "after": "high"})
        self.assertNotIn("resolved", delta["findings"])

    def test_mismatched_baseline_rejected(self):
        self.baseline["target"] = "different.test"
        with self.assertRaises(ValueError):
            compare_reports(self.report, self.baseline)

    def test_stale_derived_fields_are_not_trusted(self):
        self.report["intelligence"] = {"findings": [{"id": "invented"}]}
        self.assertEqual(len(compare_reports(self.report, self.baseline)["findings"]["persistent"]), 1)

    def test_url_normalization_preserves_query_and_nondefault_ports(self):
        self.assertEqual(canonical_url("HTTPS://APP.example.test:443#fragment"),
                         "https://app.example.test/")
        self.assertEqual(canonical_url("https://app.example.test:8443/a?x=2&x=1"),
                         "https://app.example.test:8443/a?x=2&x=1")
        self.assertEqual(canonical_url("http://[2001:db8::1]:80"), "http://[2001:db8::1]/")


class ModelMergeTests(unittest.TestCase):
    def test_subdomain_merge_preserves_sources_ips_liveness_and_stage_evidence(self):
        ctx = PipelineContext(target="example.test")
        original = StageResult(stage_index=1, subdomains=[
            Subdomain("APP.example.test.", source="crt.sh", ip_list=["192.0.2.10"]),
        ])
        ctx.merge(original)
        ctx.merge(StageResult(stage_index=2, subdomains=[
            Subdomain("app.example.test", source="subfinder", ip_list=["192.0.2.11"], is_alive=True),
        ]))
        self.assertEqual(len(ctx.all_subdomains), 1)
        merged = ctx.all_subdomains[0]
        self.assertEqual(set(merged.source.split(",")), {"crt.sh", "subfinder"})
        self.assertEqual(merged.ip_list, ["192.0.2.10", "192.0.2.11"])
        self.assertTrue(merged.is_alive)
        self.assertEqual(original.subdomains[0].ip_list, ["192.0.2.10"])
        self.assertFalse(original.subdomains[0].is_alive)

    def test_port_enrichment_does_not_inflate_counts(self):
        ctx = PipelineContext(target="example.test")
        ctx.merge(StageResult(stage_index=2, ports=[PortInfo("192.0.2.10", 443)]))
        ctx.merge(StageResult(stage_index=3, ports=[
            PortInfo("192.0.2.10", 443, service="https", product="nginx", version="1.0"),
        ]))
        report = ctx.to_final_report()
        self.assertEqual(report["summary"]["total_open_ports"], 1)
        self.assertEqual(report["ports"][0]["product"], "nginx")
        self.assertEqual(len(report["stages"]), 2)

    def test_fingerprint_merge_keeps_technologies(self):
        ctx = PipelineContext()
        ctx.merge(StageResult(fingerprints=[
            Fingerprint("https://app.example.test", technologies=[{"name": "nginx"}], title="App"),
        ]))
        ctx.merge(StageResult(fingerprints=[
            Fingerprint("https://app.example.test:443/", technologies=[{"name": "Django"}]),
        ]))
        self.assertEqual(len(ctx.all_fingerprints), 1)
        self.assertEqual(ctx.all_fingerprints[0].title, "App")
        self.assertEqual(len(ctx.all_fingerprints[0].technologies), 2)

    def test_vulnerability_reference_and_thoughts_survive_serialization(self):
        result = StageResult(stage_index=5, vulnerabilities=[
            Vulnerability(template_id="demo", url="https://app.example.test", severity="high",
                          reference=["https://example.test/advisory"], extraction="private-value"),
        ], raw_data={"agent_thoughts": [{"source": "rule", "thought": "Summary"}]})
        ctx = PipelineContext(target="example.test")
        ctx.merge(result)
        report = ctx.to_final_report()
        self.assertEqual(report["vulnerabilities"][0]["reference"], ["https://example.test/advisory"])
        self.assertNotIn("private-value", json.dumps(report))
        self.assertEqual(report["agent_thoughts"][0]["stage"], 5)


if __name__ == "__main__":
    unittest.main()
