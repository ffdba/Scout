from __future__ import annotations

import httpx

from core.config import Config
from core.models import Subdomain
from utils.logger import get_logger

logger = get_logger("hunter")


class HunterTool:
    BASE_URL = "https://hunter.qianxin.com/openApi/search"

    def __init__(self, config: Config):
        self.config = config
        self.api_key = config.get("hunter", "api_key", default="")

    async def search(self, domain: str) -> list[Subdomain]:
        if not self.api_key:
            logger.warning("Hunter API Key 未配置，跳过")
            return []
        logger.info(f"Hunter 查询: {domain}")
        results: list[Subdomain] = []
        try:
            async with httpx.AsyncClient(timeout=30, verify=False) as client:
                query = f"domain.suffix=\"{domain}\""
                resp = await client.get(
                    self.BASE_URL,
                    params={"api-key": self.api_key, "search": query, "page": 1, "page_size": 200},
                )
                if resp.status_code != 200:
                    logger.warning(f"Hunter 返回 {resp.status_code}")
                    return results
                data = resp.json()
                seen: set[str] = set()
                for item in data.get("data", {}).get("arr", []):
                    host = item.get("domain", "")
                    ip = item.get("ip", "")
                    if host and host not in seen:
                        seen.add(host)
                        results.append(Subdomain(
                            domain=host,
                            source="hunter",
                            ip_list=[ip] if ip else [],
                        ))
                logger.info(f"Hunter 发现 {len(results)} 个子域")
        except Exception as e:
            logger.error(f"Hunter 查询失败: {e}")
        return results
