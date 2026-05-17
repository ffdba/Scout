from __future__ import annotations

from core.config import Config
from core.models import PipelineContext, StageResult, Subdomain, PortInfo
from core.stage import BaseStage
from tools.subfinder import SubfinderTool
from tools.portscan import RustScanTool, NaabuTool


class Stage2Boundary(BaseStage):
    name = "边界拓展与初筛"
    index = 2

    def __init__(self, config: Config):
        super().__init__(config)
        self.subfinder = SubfinderTool(config)
        engine = config.get("portscan", "engine", default="rustscan")
        if engine == "naabu":
            self.portscan = NaabuTool(config)
        else:
            self.portscan = RustScanTool(config)

    async def run(self, ctx: PipelineContext) -> StageResult:
        self._log_start(ctx.target)
        result = self._make_result()

        await self.think(ctx)

        self.think_step(f"Subfinder 主动枚举子域: {ctx.target}")
        new_subs = await self.subfinder.enumerate(ctx.target)
        result.subdomains.extend(new_subs)
        self.think_step(f"Subfinder 发现 {len(new_subs)} 个新子域")

        ctx.merge(StageResult(stage_name="temp", stage_index=0, subdomains=new_subs))
        ctx.deduplicate_subdomains()
        self.think_step(f"去重后共 {len(ctx.all_subdomains)} 个唯一子域")

        alive_hosts = list({s.domain for s in ctx.all_subdomains if s.domain})
        self.logger.info(f"待扫描端口的主机数: {len(alive_hosts)}")

        if alive_hosts:
            self.think_step(f"端口扫描 {len(alive_hosts)} 个主机...")
            ports = await self.portscan.scan(alive_hosts)
            result.ports.extend(ports)
            self.think_step(f"发现 {len(ports)} 个开放端口")

            high_risk = [p for p in ports if p.port in (22, 23, 3389, 6379, 27017, 9200, 5432, 3306)]
            if high_risk:
                services = [f"{p.ip}:{p.port}" for p in high_risk[:5]]
                self.think_step(f"⚠️ 高危端口: {', '.join(services)}")

        result.raw_data["agent_thoughts"] = self._thoughts
        self._log_done(result)
        return result
