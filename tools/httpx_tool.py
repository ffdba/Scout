from __future__ import annotations

import json

from core.config import Config
from core.models import Fingerprint
from utils.logger import get_logger
from utils.runner import run_async, check_tool_exists

logger = get_logger("httpx")


class HttpxTool:
    def __init__(self, config: Config):
        self.config = config
        self.timeout = config.get("httpx", "timeout", default=30)
        self.threads = config.get("httpx", "threads", default=25)
        self.follow_redirects = config.get("httpx", "follow_redirects", default=True)
        self.status_codes = config.get("httpx", "status_codes", default=True)
        self.tech_detect = config.get("httpx", "tech_detect", default=True)

    async def probe(self, urls_or_hosts: list[str]) -> list[Fingerprint]:
        if not check_tool_exists("httpx"):
            logger.warning("httpx 未安装，跳过 HTTP 探测")
            return []

        if not urls_or_hosts:
            return []

        logger.info(f"Httpx 探测 {len(urls_or_hosts)} 个目标")
        import tempfile
        from pathlib import Path

        tmp_input = tempfile.mktemp(suffix=".txt")
        tmp_output = tempfile.mktemp(suffix=".json")

        Path(tmp_input).write_text("\n".join(urls_or_hosts), encoding="utf-8")

        cmd = [
            "httpx",
            "-l", tmp_input,
            "-json",
            "-o", tmp_output,
            "-t", str(self.threads),
            "-timeout", str(self.timeout),
        ]
        if self.follow_redirects:
            cmd.append("-follow-redirects")
        if self.tech_detect:
            cmd.append("-tech-detect")
        if self.status_codes:
            cmd.append("-status-code")

        result = await run_async(cmd, timeout=self.timeout * len(urls_or_hosts) // 10 + 60)
        fingerprints: list[Fingerprint] = []

        try:
            out_path = Path(tmp_output)
            if out_path.exists():
                for line in out_path.read_text(encoding="utf-8").strip().splitlines():
                    try:
                        data = json.loads(line)
                        techs = []
                        for t in data.get("tech", []):
                            if isinstance(t, dict):
                                techs.append({"name": t.get("name", ""), "version": t.get("version", "")})
                            else:
                                techs.append({"name": str(t), "version": ""})
                        fingerprints.append(Fingerprint(
                            url=data.get("url", ""),
                            technologies=techs,
                            server=data.get("webserver", ""),
                            status_code=data.get("status_code", 0),
                            title=data.get("title", ""),
                            content_length=data.get("content_length", 0),
                        ))
                    except json.JSONDecodeError:
                        continue
                out_path.unlink(missing_ok=True)
            Path(tmp_input).unlink(missing_ok=True)
        except Exception as e:
            logger.error(f"Httpx 结果解析失败: {e}")

        logger.info(f"Httpx 探测到 {len(fingerprints)} 个存活目标")
        return fingerprints
