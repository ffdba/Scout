from __future__ import annotations

import json
from typing import Any

from core.config import Config
from core.models import PipelineContext
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
            ctx.raw_data["ai_analysis"] = ai_analysis
            logger.info("AI 分析完成，已附加到报告")
        return ctx

    async def _ai_analyze(self, ctx: PipelineContext) -> str | None:
        api_key = self.config.get("ai", "api_key")
        if not api_key:
            logger.warning("AI API Key 未配置，跳过 AI 分析")
            return None

        report = ctx.to_final_report()
        prompt = (
            "你是一名资深红队安全专家。请根据以下自动化渗透测试结果，"
            "给出专业的安全评估和攻击路径建议：\n\n"
            f"目标: {ctx.target}\n"
            f"子域数量: {len(ctx.all_subdomains)}\n"
            f"开放端口数: {len(ctx.all_ports)}\n"
            f"发现漏洞数: {len(ctx.all_vulnerabilities)}\n"
            f"凭据泄露数: {len(ctx.all_credential_leaks)}\n\n"
            "漏洞详情:\n"
        )
        for v in ctx.all_vulnerabilities[:20]:
            prompt += f"  - [{v.severity}] {v.name} @ {v.matched_at}\n"
        prompt += "\n请给出：1) 整体风险评级 2) 关键攻击路径 3) 修复优先级建议"

        try:
            from openai import AsyncOpenAI
            base_url = self.config.get("ai", "base_url", default="https://api.openai.com/v1")
            model = self.config.get("ai", "model", default="gpt-4o")
            client = AsyncOpenAI(api_key=api_key, base_url=base_url)
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
