from __future__ import annotations

import json

from core.config import Config
from core.models import Vulnerability
from utils.logger import get_logger
from utils.runner import run_async, check_tool_exists

logger = get_logger("nuclei")


class NucleiTool:
    def __init__(self, config: Config):
        self.config = config
        self.timeout = config.get("nuclei", "timeout", default=600)
        self.templates = config.get("nuclei", "templates", default="")
        self.severity = config.get("nuclei", "severity", default="low,medium,high,critical")
        self.tags = config.get("nuclei", "tags", default="")
        self.rate_limit = config.get("nuclei", "rate_limit", default=150)

    async def scan(self, targets: list[str], extra_tags: str = "") -> list[Vulnerability]:
        if not check_tool_exists("nuclei"):
            logger.warning("nuclei 未安装，跳过漏洞验证")
            return []

        if not targets:
            return []

        logger.info(f"Nuclei 扫描 {len(targets)} 个目标")
        import tempfile
        from pathlib import Path

        tmp_input = tempfile.mktemp(suffix=".txt")
        tmp_output = tempfile.mktemp(suffix=".jsonl")

        Path(tmp_input).write_text("\n".join(targets), encoding="utf-8")

        cmd = [
            "nuclei",
            "-l", tmp_input,
            "-jsonl",
            "-o", tmp_output,
            "-severity", self.severity,
            "-rate-limit", str(self.rate_limit),
            "-silent",
        ]

        if self.templates:
            cmd.extend(["-t", self.templates])

        effective_tags = self.tags
        if extra_tags:
            effective_tags = f"{self.tags},{extra_tags}" if self.tags else extra_tags
        if effective_tags:
            cmd.extend(["-tags", effective_tags])

        result = await run_async(cmd, timeout=self.timeout)
        vulns: list[Vulnerability] = []

        try:
            out_path = Path(tmp_output)
            if out_path.exists():
                for line in out_path.read_text(encoding="utf-8").strip().splitlines():
                    try:
                        data = json.loads(line)
                        vulns.append(Vulnerability(
                            template_id=data.get("template-id", ""),
                            name=data.get("info", {}).get("name", ""),
                            severity=data.get("info", {}).get("severity", ""),
                            url=data.get("host", ""),
                            matched_at=data.get("matched-at", data.get("host", "")),
                            type=data.get("type", ""),
                            description=data.get("info", {}).get("description", ""),
                            reference=data.get("info", {}).get("reference", []),
                            extraction=data.get("extracted-results", [""])[0] if data.get("extracted-results") else "",
                        ))
                    except json.JSONDecodeError:
                        continue
                out_path.unlink(missing_ok=True)
            Path(tmp_input).unlink(missing_ok=True)
        except Exception as e:
            logger.error(f"Nuclei 结果解析失败: {e}")

        logger.info(f"Nuclei 发现 {len(vulns)} 个漏洞")
        return vulns
