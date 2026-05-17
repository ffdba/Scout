from __future__ import annotations

from core.config import Config
from core.models import PipelineContext, StageResult, Vulnerability
from core.stage import BaseStage
from tools.nuclei import NucleiTool


class Stage5Vuln(BaseStage):
    name = "原子化漏洞验证"
    index = 5

    TAG_MAP: dict[str, str] = {
        "wordpress": "wordpress",
        "joomla": "joomla",
        "drupal": "drupal",
        "apache": "apache",
        "nginx": "nginx",
        "iis": "iis",
        "tomcat": "tomcat",
        "spring": "spring",
        "django": "django",
        "flask": "flask",
        "laravel": "laravel",
        "thinkphp": "thinkphp",
        "shiro": "shiro",
        "fastjson": "fastjson",
        "struts": "struts2",
        "weblogic": "weblogic",
    }

    def __init__(self, config: Config):
        super().__init__(config)
        self.nuclei = NucleiTool(config)

    async def run(self, ctx: PipelineContext) -> StageResult:
        self._log_start(ctx.target)
        result = self._make_result()

        await self.think(ctx)

        targets = list({f.url for f in ctx.all_fingerprints if f.url})
        if not targets:
            hosts = list({s.domain for s in ctx.all_subdomains if s.domain})
            ips = list({p.ip for p in ctx.all_ports if p.ip})
            targets = [f"https://{h}" for h in hosts] + [f"http://{ip}" for ip in ips]

        extra_tags = self._derive_tags(ctx)

        if targets:
            self.think_step(f"Nuclei 验证 {len(targets)} 个目标, 标签: {extra_tags or '全部'}")
            vulns = await self.nuclei.scan(targets, extra_tags=extra_tags)
            result.vulnerabilities.extend(vulns)

            if vulns:
                critical = [v for v in vulns if v.severity == "critical"]
                high = [v for v in vulns if v.severity == "high"]
                if critical:
                    self.think_step(f"🔴 发现 {len(critical)} 个严重漏洞！")
                if high:
                    self.think_step(f"🟠 发现 {len(high)} 个高危漏洞")
                self.think_step(f"漏洞汇总: critical={len(critical)}, high={len(high)}, total={len(vulns)}")
            else:
                self.think_step("Nuclei 未发现已验证漏洞")

        result.raw_data["agent_thoughts"] = self._thoughts
        self._log_done(result)
        return result

    def _derive_tags(self, ctx: PipelineContext) -> str:
        tech_names: set[str] = set()
        for fp in ctx.all_fingerprints:
            for tech in fp.technologies:
                name = tech.get("name", "").lower()
                tech_names.add(name)

        matched_tags: list[str] = []
        for tech_name in tech_names:
            for keyword, tag in self.TAG_MAP.items():
                if keyword in tech_name:
                    matched_tags.append(tag)

        deduped = list(dict.fromkeys(matched_tags))
        if deduped:
            self.think_step(f"Agent 标签路由: {tech_names} -> Nuclei 标签 {deduped}")
        return ",".join(deduped)
