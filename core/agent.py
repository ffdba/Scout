from __future__ import annotations

import json
from typing import Any

from core.config import Config
from core.models import PipelineContext, StageResult
from core.pipeline import Pipeline
from core.stage import BaseStage
from stages.stage1_osint import Stage1OSINT
from stages.stage2_boundary import Stage2Boundary
from stages.stage3_fingerprint import Stage3Fingerprint
from stages.stage4_content import Stage4Content
from stages.stage5_vuln import Stage5Vuln
from utils.logger import get_logger

logger = get_logger("agent")


class RedAgent:
    STAGE_MAP: dict[str, type[BaseStage]] = {
        "1": Stage1OSINT,
        "2": Stage2Boundary,
        "3": Stage3Fingerprint,
        "4": Stage4Content,
        "5": Stage5Vuln,
    }

    def __init__(self, config: Config):
        self.config = config
        self.pipeline = Pipeline(config)

    def _build_pipeline(self, stages: list[str] | None = None):
        self.pipeline = Pipeline(self.config)
        selected = stages or list(self.STAGE_MAP.keys())
        for s in selected:
            cls = self.STAGE_MAP.get(s)
            if cls:
                self.pipeline.register(cls)
            else:
                logger.warning(f"未知阶段标识: {s}")

    async def run(self, target: str, stages: list[str] | None = None) -> PipelineContext:
        self._build_pipeline(stages)
        ctx = await self.pipeline.execute(target)
        self._print_summary(ctx)
        return ctx

    async def run_with_ai(self, target: str, stages: list[str] | None = None) -> PipelineContext:
        ctx = await self.run(target, stages)
        ai_analysis = await self._ai_analyze(ctx)
        if ai_analysis:
            ctx.ai_analysis = ai_analysis
            logger.info("AI 分析完成，已附加到报告")
        return ctx

    async def run_agentic(self, target: str, stages: list[str] | None = None) -> PipelineContext:
        if not self.config.get("ai", "api_key"):
            logger.warning("AI API Key 未配置，无法启用 agentic 决策，回退到线性流水线")
            return await self.run(target, stages)

        self._build_pipeline(stages)
        ctx = PipelineContext(target=target)
        logger.info(f"Agentic 模式启动: {target} | 阶段数: {len(self.pipeline.stages)}")

        max_steps = int(self.config.get("agent", "max_steps", default=8))
        completed: list[str] = []
        skip_stage_ids: set[str] = set()

        for step_index, stage in enumerate(self.pipeline.stages, start=1):
            if step_index > max_steps:
                logger.warning(f"达到 agent 最大步数限制: {max_steps}")
                break
            stage_id = str(stage.index)
            if stage_id in skip_stage_ids:
                logger.info(f"Agent 跳过阶段 {stage.index}: {stage.name}")
                continue

            stage.logger.info(f"Agent 执行阶段 {stage.index}: {stage.name}")
            try:
                result: StageResult = await stage.run(ctx)
                ctx.merge(result)
                stage._log_done(result)
            except Exception as e:
                logger.error(f"阶段 {stage.index} ({stage.name}) 异常: {e}")
                result = StageResult(
                    stage_name=stage.name,
                    stage_index=stage.index,
                    errors=[str(e)],
                )
                ctx.merge(result)

            completed.append(str(stage.index))
            decision = await self._ai_decide_next(ctx, stage, result, completed)
            if decision:
                ctx.agent_decisions.append(decision)
                reason = decision.get("reason") or decision.get("summary") or ""
                logger.info(f"Agent 决策: {reason}")
                for skip_id in decision.get("skip_stage_ids", []) or []:
                    skip_id = str(skip_id)
                    if skip_id in self.STAGE_MAP and skip_id not in completed:
                        skip_stage_ids.add(skip_id)
                if decision.get("stop") is True:
                    logger.info("Agent 决策停止后续阶段")
                    break

        self._print_summary(ctx)
        ai_analysis = await self._ai_analyze(ctx)
        if ai_analysis:
            ctx.ai_analysis = ai_analysis
            logger.info("AI 最终分析完成，已附加到报告")
        return ctx

    async def _ai_decide_next(
        self,
        ctx: PipelineContext,
        stage: BaseStage,
        result: StageResult,
        completed: list[str],
    ) -> dict[str, Any] | None:
        api_key = self.config.get("ai", "api_key")
        if not api_key:
            return None

        decision_prompt = self._build_decision_prompt(ctx, stage, result, completed)

        try:
            import httpx
            from openai import AsyncOpenAI

            base_url = self.config.get("ai", "base_url", default="https://api.openai.com/v1")
            model = self.config.get("ai", "model", default="gpt-4o")
            client = AsyncOpenAI(
                api_key=api_key,
                base_url=base_url,
                timeout=httpx.Timeout(20.0, connect=5.0),
            )
            resp = await client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": decision_prompt}],
                temperature=0.1,
                max_tokens=1200,
            )
            content = resp.choices[0].message.content or ""
            return self._parse_decision(content, stage, completed)
        except Exception as e:
            logger.error(f"Agent 决策失败: {e}")
            return {
                "stage": stage.index,
                "stage_name": stage.name,
                "completed": completed,
                "stop": False,
                "reason": f"AI decision failed, continue linear pipeline: {e}",
            }

    def _build_decision_prompt(
        self,
        ctx: PipelineContext,
        stage: BaseStage,
        result: StageResult,
        completed: list[str],
    ) -> str:
        observation = {
            "target": ctx.target,
            "completed_stages": completed,
            "available_stage_ids": list(self.STAGE_MAP.keys()),
            "current_stage": {"index": stage.index, "name": stage.name},
            "current_result": result.to_dict(),
            "summary": ctx.to_final_report()["summary"],
            "sample_subdomains": [s.domain for s in ctx.all_subdomains[:20]],
            "sample_ports": [f"{p.ip}:{p.port}/{p.service or 'unknown'}" for p in ctx.all_ports[:30]],
            "sample_urls": [f.url for f in ctx.all_fingerprints[:20]],
            "sample_vulnerabilities": [
                {"severity": v.severity, "name": v.name, "matched_at": v.matched_at}
                for v in ctx.all_vulnerabilities[:20]
            ],
        }
        observation_json = json.dumps(observation, ensure_ascii=False)
        if len(observation_json) > 30000:
            observation_json = observation_json[:30000] + "\n...<observation truncated>..."

        return (
            "你是 RedAgent 的决策层。你只能在用户授权范围内做安全测试规划，"
            "不能建议破坏性利用、持久化、绕过检测、数据窃取或越权行动。\n\n"
            "请根据观察结果输出一个 JSON 对象，不要输出 Markdown。字段：\n"
            "{\n"
            '  "stop": false,\n'
            '  "reason": "是否继续以及原因",\n'
            '  "priority_targets": ["最值得继续看的目标"],\n'
            '  "hypotheses": ["基于证据的风险假设"],\n'
            '  "skip_stage_ids": ["可选；如果证据显示某些后续阶段没有价值，只能填 1-5 中尚未完成的阶段编号"],\n'
            '  "operator_notes": ["给操作员的下一步人工验证建议"],\n'
            '  "confidence": "low|medium|high"\n'
            "}\n\n"
            f"观察结果 JSON:\n{observation_json}\n"
        )

    def _parse_decision(self, content: str, stage: BaseStage, completed: list[str]) -> dict[str, Any]:
        start = content.find("{")
        end = content.rfind("}")
        if start >= 0 and end > start:
            try:
                decision = json.loads(content[start:end + 1])
                if isinstance(decision, dict):
                    decision.setdefault("stage", stage.index)
                    decision.setdefault("stage_name", stage.name)
                    decision.setdefault("completed", list(completed))
                    decision.setdefault("stop", False)
                    return decision
            except json.JSONDecodeError:
                pass

        return {
            "stage": stage.index,
            "stage_name": stage.name,
            "completed": list(completed),
            "stop": False,
            "reason": "AI decision was not valid JSON; continue linear pipeline.",
            "raw": content[:1000],
        }

    async def _ai_analyze(self, ctx: PipelineContext) -> str | None:
        api_key = self.config.get("ai", "api_key")
        if not api_key:
            logger.warning("AI API Key 未配置，跳过 AI 分析")
            return None

        prompt = self._build_ai_analysis_prompt(ctx)

        try:
            import httpx
            from openai import AsyncOpenAI
            base_url = self.config.get("ai", "base_url", default="https://api.openai.com/v1")
            model = self.config.get("ai", "model", default="gpt-4o")
            client = AsyncOpenAI(
                api_key=api_key,
                base_url=base_url,
                timeout=httpx.Timeout(30.0, connect=5.0),
            )
            resp = await client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=self.config.get("ai", "temperature", default=0.2),
                max_tokens=self.config.get("ai", "max_tokens", default=4096),
            )
            return resp.choices[0].message.content
        except Exception as e:
            logger.error(f"AI 分析失败: {e}")
            return None

    def _build_ai_analysis_prompt(self, ctx: PipelineContext) -> str:
        report = ctx.to_final_report()
        compact_report = json.dumps(report, ensure_ascii=False)
        if len(compact_report) > 50000:
            compact_report = compact_report[:50000] + "\n...<report truncated>..."

        return (
            "你是一名资深红队安全顾问。以下数据来自用户授权范围内的自动化安全测试报告。"
            "请基于证据做分析，不要编造不存在的发现；不要提供破坏性利用、持久化、绕过检测或数据窃取步骤。\n\n"
            "请输出 Markdown，包含：\n"
            "1. 执行摘要和整体风险评级\n"
            "2. 关键攻击面优先级\n"
            "3. 建议的人工验证/渗透测试思路，按阶段排列\n"
            "4. 需要补充采集的信息\n"
            "5. 修复与加固优先级\n"
            "6. 下一轮自动化扫描建议\n\n"
            f"目标: {ctx.target}\n"
            f"报告 JSON:\n{compact_report}\n"
        )

    def _print_summary(self, ctx: PipelineContext):
        report = ctx.to_final_report()
        summary = report["summary"]
        logger.info("=" * 60)
        logger.info(f"目标: {ctx.target} | 渗透测试完成")
        logger.info(f"  子域: {summary['total_subdomains']}")
        logger.info(f"  端口: {summary['total_open_ports']}")
        logger.info(f"  指纹: {summary['total_fingerprints']}")
        logger.info(f"  敏感路径: {summary['total_sensitive_paths']}")
        logger.info(f"  漏洞: {summary['total_vulnerabilities']}")
        sev = summary["vulnerability_by_severity"]
        if sev:
            logger.info(f"  漏洞级别: {sev}")
        logger.info(f"  凭据泄露: {summary['total_credential_leaks']}")
        logger.info("=" * 60)
