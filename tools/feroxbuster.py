from __future__ import annotations

from pathlib import Path

from core.config import Config
from core.models import SensitivePath
from utils.logger import get_logger
from utils.runner import run_async, check_tool_exists

logger = get_logger("feroxbuster")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_LOCAL_WORDLIST = _PROJECT_ROOT / "wordlists" / "raft-medium-directories.txt"
_SYSTEM_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"


class FeroxbusterTool:
    def __init__(self, config: Config):
        self.config = config
        self.timeout = config.get("feroxbuster", "timeout", default=300)
        self.threads = config.get("feroxbuster", "threads", default=50)
        self.wordlist = config.get("feroxbuster", "wordlist", default="")
        if not self.wordlist:
            if _LOCAL_WORDLIST.exists():
                self.wordlist = str(_LOCAL_WORDLIST)
            else:
                self.wordlist = _SYSTEM_WORDLIST
        self.status_codes = config.get("feroxbuster", "status_codes",
                                       default="200,204,301,302,307,401,403")
        self.extensions = config.get("feroxbuster", "extensions",
                                     default="php,asp,aspx,jsp,html,js,bak,old,zip,tar.gz,sql,conf,env,yml,yaml,json,xml")

    async def scan(self, urls: list[str]) -> list[SensitivePath]:
        if not check_tool_exists("feroxbuster"):
            logger.warning("feroxbuster 未安装，跳过目录爆破")
            return []

        all_paths: list[SensitivePath] = []
        for url in urls:
            logger.info(f"Feroxbuster 爆破: {url}")
            cmd = [
                "feroxbuster",
                "-u", url,
                "-t", str(self.threads),
                "-w", self.wordlist,
                "-x", self.extensions,
                "-s", self.status_codes,
                "--no-state",
                "-q",
            ]

            proxy = self.config.get("proxy", "http")
            if self.config.get("proxy", "enabled", default=False) and proxy:
                cmd.extend(["-p", proxy])

            result = await run_async(cmd, timeout=self.timeout)
            if result.success:
                for line in result.stdout.strip().splitlines():
                    line = line.strip()
                    if line.startswith("http"):
                        parts = line.split()
                        url_part = parts[0] if parts else line
                        status = 0
                        length = 0
                        for part in parts[1:]:
                            if part.isdigit() and 100 <= int(part) <= 599:
                                status = int(part)
                            elif part.isdigit():
                                length = int(part)
                        all_paths.append(SensitivePath(
                            url=url_part,
                            status_code=status,
                            content_length=length,
                            path_type=self._classify(url_part, status),
                        ))

        logger.info(f"Feroxbuster 发现 {len(all_paths)} 个路径")
        return all_paths

    def _classify(self, url: str, status: int) -> str:
        lower = url.lower()
        if status == 401:
            return "需认证路径"
        if status == 403:
            return "禁止访问(可能绕过)"
        if ".bak" in lower or ".old" in lower or "backup" in lower:
            return "备份文件"
        if ".env" in lower or ".conf" in lower or ".yaml" in lower or ".yml" in lower:
            return "配置文件"
        if ".sql" in lower or ".db" in lower:
            return "数据库文件"
        if "admin" in lower or "manage" in lower:
            return "管理后台"
        if "upload" in lower:
            return "上传接口"
        return "目录探测"
