from __future__ import annotations

import json

from core.config import Config
from core.models import CredentialLeak
from utils.logger import get_logger
from utils.runner import run_async, check_tool_exists

logger = get_logger("gitleaks")


class GitleaksTool:
    def __init__(self, config: Config):
        self.config = config
        self.repo_path = config.get("gitleaks", "repo_path", default="")

    async def scan(self, target: str) -> list[CredentialLeak]:
        if not check_tool_exists("gitleaks"):
            logger.warning("gitleaks 未安装，跳过凭据泄露扫描")
            return []

        logger.info(f"Gitleaks 扫描目标相关仓库: {target}")
        results: list[CredentialLeak] = []

        if self.repo_path:
            leaks = await self._scan_repo(self.repo_path)
            results.extend(leaks)
        else:
            logger.info("未指定 repo_path，跳过本地仓库扫描")

        return results

    async def _scan_repo(self, repo_path: str) -> list[CredentialLeak]:
        import tempfile
        from pathlib import Path

        tmp = tempfile.mktemp(suffix=".json")
        cmd = [
            "gitleaks", "detect",
            "--source", repo_path,
            "--report-format", "json",
            "--report-path", tmp,
            "--no-banner",
        ]
        result = await run_async(cmd, timeout=300)
        leaks: list[CredentialLeak] = []

        try:
            report_path = Path(tmp)
            if report_path.exists():
                data = json.loads(report_path.read_text(encoding="utf-8"))
                for item in data:
                    leaks.append(CredentialLeak(
                        source="gitleaks",
                        repo=repo_path,
                        file=item.get("File", ""),
                        rule=item.get("RuleID", ""),
                        secret_type=item.get("RuleDescription", ""),
                        match=item.get("Match", "")[:100],
                    ))
                report_path.unlink(missing_ok=True)
        except Exception as e:
            logger.error(f"Gitleaks 报告解析失败: {e}")

        logger.info(f"Gitleaks 发现 {len(leaks)} 处凭据泄露")
        return leaks
