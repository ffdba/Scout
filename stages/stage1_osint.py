from __future__ import annotations

import asyncio

from core.config import Config
from core.models import PipelineContext, StageResult, Subdomain, CredentialLeak
from core.stage import BaseStage
from tools.crtsh import CrtshTool
from tools.quake import QuakeTool
from tools.hunter import HunterTool
from tools.gitleaks import GitleaksTool


class Stage1OSINT(BaseStage):
    name = "隐蔽OSINT"
    index = 1

    def __init__(self, config: Config):
        super().__init__(config)
        self.crtsh = CrtshTool(config)
        self.quake = QuakeTool(config)
        self.hunter = HunterTool(config)
        self.gitleaks = GitleaksTool(config)

    async def run(self, ctx: PipelineContext) -> StageResult:
        self._log_start(ctx.target)
        result = self._make_result()

        await self.think(ctx)

        self.think_step("启动 crt.sh / Quake / Hunter / Gitleaks 并行侦察...")

        crtsh_task = self.crtsh.query(ctx.target)
        quake_task = self.quake.search_subdomains(ctx.target)
        hunter_task = self.hunter.search(ctx.target)
        gitleaks_task = self.gitleaks.scan(ctx.target)

        crtsh_subs, quake_subs, hunter_subs, leaks = await asyncio.gather(
            crtsh_task, quake_task, hunter_task, gitleaks_task,
            return_exceptions=True,
        )

        if isinstance(crtsh_subs, list):
            result.subdomains.extend(crtsh_subs)
            self.think_step(f"crt.sh 返回 {len(crtsh_subs)} 个子域")
        else:
            result.errors.append(f"crt.sh: {crtsh_subs}")

        if isinstance(quake_subs, list):
            result.subdomains.extend(quake_subs)
            self.think_step(f"Quake 返回 {len(quake_subs)} 个子域")
        else:
            result.errors.append(f"quake: {quake_subs}")

        if isinstance(hunter_subs, list):
            result.subdomains.extend(hunter_subs)
            self.think_step(f"Hunter 返回 {len(hunter_subs)} 个子域")
        else:
            result.errors.append(f"hunter: {hunter_subs}")

        if isinstance(leaks, list):
            result.credential_leaks.extend(leaks)
            if leaks:
                self.think_step(f"⚠️ Gitleaks 发现 {len(leaks)} 处凭据泄露！")
        else:
            result.errors.append(f"gitleaks: {leaks}")

        quake_ips = []
        try:
            quake_ips = await self.quake.search_ips(ctx.target)
            if quake_ips:
                self.think_step(f"Quake 发现 {len(quake_ips)} 个历史IP (潜在源站)")
        except Exception as e:
            result.errors.append(f"quake_ips: {e}")

        self.think_step(f"OSINT 汇总: {len(result.subdomains)} 个子域, {len(result.credential_leaks)} 处泄露")

        result.raw_data = {
            "quake_historical_ips": quake_ips,
            "total_sources": sum(1 for x in [crtsh_subs, quake_subs, hunter_subs] if isinstance(x, list) and len(x) > 0),
            "agent_thoughts": self._thoughts,
        }

        self._log_done(result)
        return result
