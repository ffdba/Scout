from __future__ import annotations

import json

import httpx

from core.config import Config
from core.models import Subdomain, PortInfo
from utils.logger import get_logger

logger = get_logger("quake")


class QuakeTool:
    BASE_URL = "https://quake.360.net/api/v3"

    def __init__(self, config: Config):
        self.config = config
        self.api_key = config.get("quake", "api_key", default="")

    def _headers(self) -> dict[str, str]:
        return {"X-QuakeToken": self.api_key, "Content-Type": "application/json"}

    async def search_subdomains(self, domain: str) -> list[Subdomain]:
        if not self.api_key:
            logger.warning("Quake API Key 未配置，跳过")
            return []
        logger.info(f"Quake 查询子域: {domain}")
        results: list[Subdomain] = []
        try:
            async with httpx.AsyncClient(timeout=30, verify=False) as client:
                resp = await client.post(
                    f"{self.BASE_URL}/search/quake_service",
                    headers=self._headers(),
                    json={"query": f"domain:\"{domain}\"", "start": 0, "size": 500},
                )
                if resp.status_code != 200:
                    logger.warning(f"Quake 返回 {resp.status_code}: {resp.text[:200]}")
                    return results
                data = resp.json()
                seen: set[str] = set()
                for item in data.get("data", []):
                    host = item.get("service", {}).get("host", "")
                    if host and host.endswith(f".{domain}") and host not in seen:
                        seen.add(host)
                        ip = item.get("ip", "")
                        results.append(Subdomain(
                            domain=host,
                            source="quake",
                            ip_list=[ip] if ip else [],
                        ))
                logger.info(f"Quake 发现 {len(results)} 个子域")
        except Exception as e:
            logger.error(f"Quake 查询失败: {e}")
        return results

    async def search_ips(self, domain: str) -> list[str]:
        if not self.api_key:
            return []
        logger.info(f"Quake 查询历史IP: {domain}")
        ips: list[str] = []
        try:
            async with httpx.AsyncClient(timeout=30, verify=False) as client:
                resp = await client.post(
                    f"{self.BASE_URL}/search/quake_service",
                    headers=self._headers(),
                    json={"query": f"domain:\"{domain}\"", "start": 0, "size": 200, "ignore_cache": False},
                )
                if resp.status_code == 200:
                    for item in resp.json().get("data", []):
                        ip = item.get("ip", "")
                        if ip and ip not in ips:
                            ips.append(ip)
        except Exception as e:
            logger.error(f"Quake IP 查询失败: {e}")
        return ips
