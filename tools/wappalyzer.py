from __future__ import annotations

import json

from core.config import Config
from core.models import Fingerprint
from utils.logger import get_logger
from utils.runner import run_async, check_tool_exists

logger = get_logger("wappalyzer")


class WappalyzerTool:
    def __init__(self, config: Config):
        self.config = config
        self.timeout = config.get("wappalyzer", "timeout", default=30)

    async def analyze(self, urls: list[str]) -> list[Fingerprint]:
        if not check_tool_exists("wappalyzer"):
            logger.warning("wappalyzer CLI 未安装，跳过技术栈识别")
            return []

        results: list[Fingerprint] = []
        for url in urls:
            logger.info(f"Wappalyzer 分析: {url}")
            cmd = ["wappalyzer", url, "--output", "json"]
            result = await run_async(cmd, timeout=self.timeout)
            if result.success and result.stdout.strip():
                try:
                    data = json.loads(result.stdout)
                    techs = []
                    technologies = data.get("technologies", [])
                    for t in technologies:
                        techs.append({
                            "name": t.get("name", ""),
                            "version": t.get("version", ""),
                            "categories": ",".join(c.get("name", "") for c in t.get("categories", [])),
                        })
                    results.append(Fingerprint(
                        url=url,
                        technologies=techs,
                    ))
                except json.JSONDecodeError:
                    logger.warning(f"Wappalyzer 输出解析失败: {url}")

        logger.info(f"Wappalyzer 识别 {len(results)} 个目标技术栈")
        return results
