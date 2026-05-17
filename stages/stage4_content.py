from __future__ import annotations

from core.config import Config
from core.models import PipelineContext, StageResult, SensitivePath
from core.stage import BaseStage
from tools.katana import KatanaTool
from tools.feroxbuster import FeroxbusterTool


class Stage4Content(BaseStage):
    name = "敏感路径深挖"
    index = 4

    def __init__(self, config: Config):
        super().__init__(config)
        self.katana = KatanaTool(config)
        self.feroxbuster = FeroxbusterTool(config)

    async def run(self, ctx: PipelineContext) -> StageResult:
        self._log_start(ctx.target)
        result = self._make_result()

        await self.think(ctx)

        alive_urls = [f.url for f in ctx.all_fingerprints if f.url and f.status_code in (200, 301, 302, 403)]
        if not alive_urls:
            hosts = list({s.domain for s in ctx.all_subdomains if s.domain})
            alive_urls = [f"https://{h}" for h in hosts]

        if alive_urls:
            self.think_step(f"Katana 动态爬网 {min(len(alive_urls), 20)} 个目标")
            crawled = await self.katana.crawl(alive_urls[:20])
            result.sensitive_paths.extend(crawled)
            sensitive = [s for s in crawled if s.path_type != "爬取路径"]
            self.think_step(f"Katana 爬取 {len(crawled)} 个路径, 其中 {len(sensitive)} 个敏感路径")

            ferox_targets = [u.rstrip("/") for u in alive_urls[:10]]
            if ferox_targets:
                self.think_step(f"Feroxbuster 目录爆破 {len(ferox_targets)} 个目标")
                discovered = await self.feroxbuster.scan(ferox_targets)
                result.sensitive_paths.extend(discovered)
                backups = [s for s in discovered if "备份" in s.path_type or "配置" in s.path_type]
                if backups:
                    self.think_step(f"⚠️ 发现 {len(backups)} 个备份/配置文件！")

        result.raw_data["agent_thoughts"] = self._thoughts
        self._log_done(result)
        return result
