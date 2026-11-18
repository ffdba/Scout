from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from core.agent import ScoutAgent
from core.config import Config
from core.models import PipelineContext, StageResult
from core.reporting import load_report
from core.stage import BaseStage

ROOT = Path(__file__).resolve().parents[1]


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.config = Config()
        self.config.raw.setdefault("output", {}).update({"dir": str(self.directory), "format": "jsonl"})
        self.config.raw.setdefault("ai", {})["api_key"] = "synthetic-no-network"
        self.agent = ScoutAgent(self.config)
        self.stage = SimpleNamespace(index=1, name="OSINT")

    def test_decision_metadata_cannot_be_overridden_by_model(self):
        decision = self.agent._parse_decision(json.dumps({
            "stage": 99, "stage_name": "Fake", "completed": ["5"], "stop": False,
            "skip_stage_ids": ["1", "3", "99", "3"], "confidence": "unsupported",
        }), self.stage, ["1"])
        self.assertEqual(decision["stage"], 1)
        self.assertEqual(decision["completed"], ["1"])
        self.assertEqual(decision["skip_stage_ids"], ["3"])
        self.assertEqual(decision["confidence"], "low")

    def test_malformed_decision_falls_back_to_continuation(self):
        for content in ('{"stop": "true"}', '{"skip_stage_ids": 5}',
                        '{"priority_targets": [42]}', "not json"):
            with self.subTest(content=content):
                decision = self.agent._parse_decision(content, self.stage, ["1"])
                self.assertFalse(decision["stop"])
                self.assertIn("continue", decision["reason"])

    def test_decision_snapshots_are_not_mutated_by_later_steps(self):
        completed = ["1"]
        decision = self.agent._parse_decision('{"stop": false}', self.stage, completed)
        completed.append("2")
        self.assertEqual(decision["completed"], ["1"])

    def test_run_with_ai_persists_once_after_analysis(self):
        ctx = PipelineContext(target="example.test")
        with patch.object(self.agent, "run", new=AsyncMock(return_value=ctx)), \
             patch.object(self.agent, "_ai_analyze", new=AsyncMock(return_value="Final analysis")):
            asyncio.run(self.agent.run_with_ai("example.test"))
        report = load_report(self.directory / "example_test_report.jsonl")
        self.assertEqual(report["ai_analysis"], "Final analysis")
        self.assertEqual(len((self.directory / "example_test_report.jsonl").read_text().splitlines()), 1)

    def test_agentic_mode_creates_output_and_persists_decisions(self):
        class SyntheticStage(BaseStage):
            name = "Synthetic"
            index = 1

            async def run(self, ctx):
                return StageResult(stage_name=self.name, stage_index=self.index)

        stage = SyntheticStage(self.config)

        def build(stages=None):
            self.agent.pipeline.stages = [stage]

        with patch.object(self.agent, "_build_pipeline", side_effect=build), \
             patch.object(self.agent, "_ai_decide_next",
                          new=AsyncMock(return_value={"stop": False, "reason": "Synthetic"})), \
             patch.object(self.agent, "_ai_analyze", new=AsyncMock(return_value="Final analysis")):
            asyncio.run(self.agent.run_agentic("example.test"))
        report = load_report(self.directory / "example_test_report.json")
        self.assertEqual(report["ai_analysis"], "Final analysis")
        self.assertEqual(len(report["agent_decisions"]), 1)
        self.assertTrue((self.directory / "example_test_assessment.md").exists())


if __name__ == "__main__":
    unittest.main()
