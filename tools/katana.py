from __future__ import annotations

from core.config import Config
from core.models import SensitivePath
from utils.logger import get_logger
from utils.runner import run_async, check_tool_exists

logger = get_logger("katana")


class KatanaTool:
    def __init__(self, config: Config):
        self.config = config
        self.timeout = config.get("katana", "timeout", default=300)
        self.depth = config.get("katana", "depth", default=3)
        self.threads = config.get("katana", "threads", default=10)
        self.js_crawl = config.get("katana", "js_crawl", default=True)
        self.autofill = config.get("katana", "autofill", default=True)

    async def crawl(self, urls: list[str]) -> list[SensitivePath]:
        if not check_tool_exists("katana"):
            logger.warning("katana 未安装，跳过动态爬网")
            return []

        all_paths: list[SensitivePath] = []
        for url in urls:
            logger.info(f"Katana 爬网: {url}")
            cmd = [
                "katana",
                "-u", url,
                "-d", str(self.depth),
                "-t", str(self.threads),
                "-silent",
                "-jc",
                "-aff",
            ]
            if self.js_crawl:
                cmd.append("-js-crawl")
            if self.autofill:
                cmd.append("-aff")

            result = await run_async(cmd, timeout=self.timeout)
            if result.success:
                for line in result.stdout.strip().splitlines():
                    line = line.strip()
                    if line.startswith("http"):
                        path_type = self._classify(line)
                        all_paths.append(SensitivePath(
                            url=line,
                            path_type=path_type,
                        ))

        logger.info(f"Katana 爬取到 {len(all_paths)} 个路径")
        return all_paths

    def _classify(self, url: str) -> str:
        lower = url.lower()
        sensitive_patterns = {
            "admin": "管理面板",
            "login": "登录入口",
            "upload": "上传接口",
            "api": "API端点",
            ".env": "环境配置",
            ".git": "Git泄露",
            ".bak": "备份文件",
            "backup": "备份文件",
            "config": "配置文件",
            "debug": "调试接口",
            "swagger": "API文档",
            "graphql": "GraphQL端点",
            "wp-admin": "WordPress管理",
            "phpmyadmin": "数据库管理",
        }
        for pattern, label in sensitive_patterns.items():
            if pattern in lower:
                return label
        return "爬取路径"
