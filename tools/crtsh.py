from __future__ import annotations

import json
from typing import Any

import httpx

from core.config import Config
from core.models import Subdomain
from utils.logger import get_logger

logger = get_logger("crtsh")


class CrtshTool:
    def __init__(self, config: Config):
        self.config = config
        self.timeout = config.get("crtsh", "timeout", default=30)

    async def query(self, domain: str) -> list[Subdomain]:
        logger.info(f"查询 crt.sh: {domain}")
        results: list[Subdomain] = []
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    logger.warning(f"crt.sh 返回状态码 {resp.status_code}")
                    return results
                data = resp.json()
                seen: set[str] = set()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        if name and name not in seen and name.endswith(f".{domain}"):
                            seen.add(name)
                            results.append(Subdomain(domain=name, source="crt.sh"))
                logger.info(f"crt.sh 发现 {len(results)} 个子域")
        except Exception as e:
            logger.error(f"crt.sh 查询失败: {e}")
        return results
