from __future__ import annotations

from core.config import Config
from core.models import Subdomain
from utils.logger import get_logger
from utils.runner import run_async, check_tool_exists

logger = get_logger("subfinder")


class SubfinderTool:
    def __init__(self, config: Config):
        self.config = config
        self.timeout = config.get("subfinder", "timeout", default=300)
        self.threads = config.get("subfinder", "threads", default=10)
        self.config_path = config.get("subfinder", "config_path", default="")

    async def enumerate(self, domain: str) -> list[Subdomain]:
        if not check_tool_exists("subfinder"):
            logger.warning("subfinder 未安装，跳过子域枚举")
            return []

        logger.info(f"Subfinder 枚举子域: {domain}")
        cmd = ["subfinder", "-d", domain, "-t", str(self.threads), "-silent"]
        if self.config_path:
            cmd.extend(["-config", self.config_path])

        result = await run_async(cmd, timeout=self.timeout)
        if not result.success:
            logger.warning(f"Subfinder 执行失败: {result.stderr[:200]}")
            return []

        subdomains: list[Subdomain] = []
        for line in result.stdout.strip().splitlines():
            line = line.strip().lower()
            if line and line.endswith(f".{domain}"):
                subdomains.append(Subdomain(domain=line, source="subfinder"))

        logger.info(f"Subfinder 发现 {len(subdomains)} 个子域")
        return subdomains
