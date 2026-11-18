from __future__ import annotations

import asyncio
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.config import Config
from core.models import PipelineContext
from core.reporting import load_report, write_report

ROOT = Path(__file__).resolve().parents[1]


class ReportingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.report = load_report(ROOT / "examples" / "demo_report.json")

    def test_output_creates_directory_and_exports_both_formats(self):
        paths = write_report(self.report, self.directory / "nested", fmt="jsonl")
        exported = load_report(paths["json"])
        self.assertEqual(exported["schema_version"], "2.0")
        self.assertIn("intelligence", exported)
        self.assertEqual(load_report(paths["jsonl"]), exported)
        markdown = paths["markdown"].read_text(encoding="utf-8")
        self.assertIn("SYNTHETIC DEMO", markdown)
        self.assertIn("Asset Priority", markdown)
        self.assertIn("#/stages/4/vulnerabilities/0", markdown)

    def test_jsonl_uses_latest_nonempty_snapshot(self):
        path = self.directory / "history.jsonl"
        path.write_text(json.dumps({"target": "old.test"}) + "\n\n"
                        + json.dumps(self.report) + "\n", encoding="utf-8")
        self.assertEqual(load_report(path)["target"], "example.test")

    def test_invalid_and_empty_reports_rejected(self):
        for content in ("", "[]", "{}", '{"target": " "}', '{"target": "x", "ports": {}}',
                        '{"target": "x", "ports": [{"port": "443"}]}',
                        '{"target": "x", "stages": [{"errors": "failed"}]}',
                        '{"target": "x", "subdomains": [{"domain": null}]}'):
            path = self.directory / "invalid.json"
            path.write_text(content, encoding="utf-8")
            with self.subTest(content=content), self.assertRaises(ValueError):
                load_report(path)
        path = self.directory / "empty.jsonl"
        path.write_text("\n\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            load_report(path)

    def test_markdown_escapes_untrusted_text(self):
        self.report["vulnerabilities"][0]["name"] = '<script>alert(1)</script> | [click](javascript:x)'
        paths = write_report(self.report, self.directory)
        text = paths["markdown"].read_text(encoding="utf-8")
        self.assertNotIn("<script>", text)
        self.assertNotIn("[click](javascript:x)", text)
        self.assertIn("\\<script\\>", text)

    def test_comparison_exported_and_stale_comparison_removed(self):
        self.report["comparison"] = {"stale": True}
        paths = write_report(self.report, self.directory)
        self.assertNotIn("comparison", load_report(paths["json"]))
        baseline = load_report(ROOT / "examples" / "demo_baseline.json")
        paths = write_report(self.report, self.directory, baseline=baseline)
        self.assertIn("comparison", load_report(paths["json"]))
        self.assertIn("Baseline Comparison", paths["markdown"].read_text(encoding="utf-8"))

    def test_unsupported_format_fails_before_writing(self):
        with self.assertRaises(ValueError):
            write_report(self.report, self.directory / "missing", fmt="csv")
        self.assertFalse((self.directory / "missing").exists())

    def test_unsafe_target_cannot_escape_output_directory(self):
        self.report["target"] = "../../outside"
        paths = write_report(self.report, self.directory)
        for path in paths.values():
            self.assertEqual(path.resolve().parent, self.directory.resolve())

    def test_ai_analysis_is_in_final_json_and_markdown(self):
        self.report["ai_analysis"] = "Final analysis"
        paths = write_report(self.report, self.directory, fmt="jsonl")
        self.assertEqual(load_report(paths["jsonl"])["ai_analysis"], "Final analysis")
        self.assertEqual(paths["ai_analysis"].read_text(encoding="utf-8"), "Final analysis")


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def test_demo_never_imports_scanner_or_loads_config(self):
        import main
        with patch("sys.argv", ["main.py", "--demo", "-o", str(self.directory)]), \
             patch.dict("sys.modules", {"core.agent": None}), \
             patch.object(Config, "_load", side_effect=AssertionError("Config must not load")), \
             contextlib.redirect_stdout(io.StringIO()):
            asyncio.run(main.main())
        report = load_report(self.directory / "example_test_report.json")
        self.assertTrue(report["demo"])
        self.assertEqual(report["intelligence"]["summary"]["tool_reported"], 2)

    def test_list_stages_needs_no_target_or_scanner(self):
        import main
        output = io.StringIO()
        with patch("sys.argv", ["main.py", "--list-stages"]), \
             patch.dict("sys.modules", {"core.agent": None}), contextlib.redirect_stdout(output):
            asyncio.run(main.main())
        self.assertIn("OSINT", output.getvalue())

    def test_no_ai_clears_key_before_any_stage_is_constructed(self):
        import main

        class FakeAgent:
            def __init__(inner, config):
                self.assertEqual(config.get("ai", "api_key"), "")

            async def run(inner, target, stages=None, *, persist=True):
                self.assertFalse(persist)
                return PipelineContext(target=target)

        with patch("sys.argv", ["main.py", "example.test", "--skip-check", "--no-ai",
                                "-o", str(self.directory)]), \
             patch.dict(os.environ, {"AI_API_KEY": "test-not-a-real-key"}), \
             patch("core.agent.ScoutAgent", FakeAgent), contextlib.redirect_stdout(io.StringIO()):
            asyncio.run(main.main())
        self.assertTrue((self.directory / "example_test_report.json").exists())

    def test_config_instances_are_isolated(self):
        with patch.dict(os.environ, {}, clear=True):
            path = self.directory / "one.yaml"
            path.write_text("ai:\n  api_key: first\n", encoding="utf-8")
            first = Config(str(path))
            path = self.directory / "two.yaml"
            path.write_text("ai:\n  api_key: second\n", encoding="utf-8")
            second = Config(str(path))
        self.assertIsNot(first, second)
        first.raw["ai"]["api_key"] = ""
        self.assertEqual(second.get("ai", "api_key"), "second")

    def test_selected_stages_only_require_their_tools(self):
        import main
        with patch("utils.runner.check_tool_exists", return_value=False), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(main.check_dependencies(["1"]))
            self.assertFalse(main.check_dependencies(["5"]))


if __name__ == "__main__":
    unittest.main()
