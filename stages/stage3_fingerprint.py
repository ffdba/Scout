from __future__ import annotations

from core.config import Config
from core.models import PipelineContext, StageResult, Fingerprint
from core.stage import BaseStage
from tools.nmap import NmapTool
from tools.httpx_tool import HttpxTool
from tools.wappalyzer import WappalyzerTool


class Stage3Fingerprint(BaseStage):
    name = "指纹深度聚焦"
    index = 3

    def __init__(self, config: Config):
        super().__init__(config)
        self.nmap = NmapTool(config)
        self.httpx = HttpxTool(config)
        self.wappalyzer = WappalyzerTool(config)

    async def run(self, ctx: PipelineContext) -> StageResult:
        self._log_start(ctx.target)
        result = self._make_result()

        await self.think(ctx)

        unique_ips = list({p.ip for p in ctx.all_ports if p.ip})
        open_ports = list({p.port for p in ctx.all_ports if p.port})
        hosts = list({s.domain for s in ctx.all_subdomains if s.domain})

        if unique_ips and open_ports:
            self.think_step(f"Nmap 定向扫描 {len(unique_ips)} 个IP的 {len(open_ports)} 个端口")
            nmap_ports = await self.nmap.scan(unique_ips, ports=open_ports)
            result.ports.extend(nmap_ports)
            services = {}
            for p in nmap_ports:
                if p.service:
                    services[p.service] = services.get(p.service, 0) + 1
            if services:
                top = sorted(services.items(), key=lambda x: -x[1])[:5]
                self.think_step(f"服务分布: {', '.join(f'{k}({v})' for k, v in top)}")

        probe_targets = []
        for host in hosts:
            probe_targets.append(f"http://{host}")
            probe_targets.append(f"https://{host}")
        for ip in unique_ips:
            probe_targets.append(f"http://{ip}")
            probe_targets.append(f"https://{ip}")

        if probe_targets:
            self.think_step(f"Httpx 探测 {len(probe_targets)} 个目标")
            httpx_fps = await self.httpx.probe(probe_targets)
            result.fingerprints.extend(httpx_fps)
            alive = [f for f in httpx_fps if f.status_code in (200, 301, 302)]
            self.think_step(f"Httpx 发现 {len(alive)} 个存活目标 (共探测 {len(httpx_fps)})")

        alive_urls = [f.url for f in result.fingerprints if f.url and f.status_code in (200, 301, 302, 403)]
        if alive_urls:
            self.think_step(f"Wappalyzer 深度识别 {min(len(alive_urls), 50)} 个目标技术栈")
            wapp_fps = await self.wappalyzer.analyze(alive_urls[:50])
            for wf in wapp_fps:
                for existing in result.fingerprints:
                    if existing.url == wf.url:
                        existing.technologies.extend(wf.technologies)
                        break
            all_techs = set()
            for f in result.fingerprints:
                for t in f.technologies:
                    all_techs.add(t.get("name", ""))
            if all_techs:
                self.think_step(f"识别到技术栈: {', '.join(list(all_techs)[:10])}")

        result.raw_data["agent_thoughts"] = self._thoughts
        self._log_done(result)
        return result
