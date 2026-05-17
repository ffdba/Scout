from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from utils.logger import get_logger

logger = get_logger("runner")

BIN_DIR = Path(__file__).resolve().parent.parent / "bin"


def resolve_tool(tool_name: str) -> str:
    bin_path = BIN_DIR / tool_name
    if bin_path.exists() and os.access(str(bin_path), os.X_OK):
        return str(bin_path)
    system_path = shutil.which(tool_name)
    if system_path:
        return system_path
    return tool_name


def check_tool_exists(tool_name: str) -> bool:
    bin_path = BIN_DIR / tool_name
    if bin_path.exists() and os.access(str(bin_path), os.X_OK):
        return True
    return shutil.which(tool_name) is not None


class CommandResult:
    def __init__(self, returncode: int, stdout: str, stderr: str, command: str):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.command = command

    @property
    def success(self) -> bool:
        return self.returncode == 0

    def __repr__(self) -> str:
        return f"CommandResult(rc={self.returncode}, cmd={self.command!r})"


def _resolve_cmd(cmd: list[str]) -> list[str]:
    if not cmd:
        return cmd
    resolved = resolve_tool(cmd[0])
    if resolved != cmd[0]:
        logger.debug(f"工具路径解析: {cmd[0]} -> {resolved}")
    return [resolved] + cmd[1:]


def run_sync(
    cmd: list[str],
    timeout: int = 300,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> CommandResult:
    cmd = _resolve_cmd(cmd)
    cmd_str = " ".join(cmd)
    logger.info(f"执行命令: {cmd_str}")
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=env,
        )
        result = CommandResult(proc.returncode, proc.stdout, proc.stderr, cmd_str)
        if not result.success:
            logger.warning(f"命令退出码 {proc.returncode}: {cmd_str}")
            if proc.stderr:
                logger.debug(f"STDERR: {proc.stderr[:500]}")
        return result
    except subprocess.TimeoutExpired:
        logger.error(f"命令超时 ({timeout}s): {cmd_str}")
        return CommandResult(-1, "", f"Timeout after {timeout}s", cmd_str)
    except FileNotFoundError:
        logger.error(f"工具未安装: {cmd[0]}")
        return CommandResult(-1, "", f"Tool not found: {cmd[0]}", cmd_str)


async def run_async(
    cmd: list[str],
    timeout: int = 300,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> CommandResult:
    cmd = _resolve_cmd(cmd)
    cmd_str = " ".join(cmd)
    logger.info(f"异步执行命令: {cmd_str}")
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=env,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        result = CommandResult(
            proc.returncode or 0,
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
            cmd_str,
        )
        if not result.success:
            logger.warning(f"命令退出码 {proc.returncode}: {cmd_str}")
        return result
    except asyncio.TimeoutError:
        logger.error(f"异步命令超时 ({timeout}s): {cmd_str}")
        return CommandResult(-1, "", f"Timeout after {timeout}s", cmd_str)
    except FileNotFoundError:
        logger.error(f"工具未安装: {cmd[0]}")
        return CommandResult(-1, "", f"Tool not found: {cmd[0]}", cmd_str)
