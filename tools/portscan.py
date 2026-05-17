from __future__ import annotations

from core.config import Config
from core.models import PortInfo
from utils.logger import get_logger
from utils.runner import run_async, check_tool_exists

logger = get_logger("portscan")


class RustScanTool:
    def __init__(self, config: Config):
        self.config = config
        self.timeout = config.get("portscan", "rustscan", "timeout", default=300)
        self.batch_size = config.get("portscan", "rustscan", "batch_size", default=512)
        self.ulimit = config.get("portscan", "rustscan", "ulimit", default=5000)

    async def scan(self, targets: list[str], ports: str = "1-65535") -> list[PortInfo]:
        if not check_tool_exists("rustscan"):
            logger.warning("rustscan 未安装，跳过端口扫描")
            return []

        all_ports: list[PortInfo] = []
        for target in targets:
            logger.info(f"RustScan 扫描: {target}")
            cmd = [
                "rustscan",
                "-a", target,
                "-p", ports,
                "--batch-size", str(self.batch_size),
                "--ulimit", str(self.ulimit),
                "--",
                "-sV",
            ]
            result = await run_async(cmd, timeout=self.timeout)
            if result.success:
                all_ports.extend(self._parse_output(result.stdout, target))

        logger.info(f"RustScan 共发现 {len(all_ports)} 个开放端口")
        return all_ports

    def _parse_output(self, output: str, default_ip: str) -> list[PortInfo]:
        ports: list[PortInfo] = []
        for line in output.splitlines():
            line = line.strip()
            if "->" in line and "Open" in line:
                try:
                    parts = line.split()
                    port_part = parts[0]
                    ip = default_ip
                    if ":" in port_part:
                        ip, port_str = port_part.rsplit(":", 1)
                        port = int(port_str)
                    else:
                        port = int(port_part)
                    ports.append(PortInfo(ip=ip, port=port, service=""))
                except (ValueError, IndexError):
                    continue
        return ports


class NaabuTool:
    def __init__(self, config: Config):
        self.config = config
        self.timeout = config.get("portscan", "naabu", "timeout", default=300)
        self.rate = config.get("portscan", "naabu", "rate", default=1000)
        self.top_ports = config.get("portscan", "naabu", "top_ports", default=1000)

    async def scan(self, targets: list[str]) -> list[PortInfo]:
        if not check_tool_exists("naabu"):
            logger.warning("naabu 未安装，跳过端口扫描")
            return []

        all_ports: list[PortInfo] = []
        for target in targets:
            logger.info(f"Naabu 扫描: {target}")
            cmd = [
                "naabu",
                "-host", target,
                "-top-ports", str(self.top_ports),
                "-rate", str(self.rate),
                "-silent",
            ]
            result = await run_async(cmd, timeout=self.timeout)
            if result.success:
                all_ports.extend(self._parse_output(result.stdout, target))

        logger.info(f"Naabu 共发现 {len(all_ports)} 个开放端口")
        return all_ports

    def _parse_output(self, output: str, default_ip: str) -> list[PortInfo]:
        ports: list[PortInfo] = []
        for line in output.strip().splitlines():
            line = line.strip()
            if ":" in line:
                try:
                    ip, port_str = line.rsplit(":", 1)
                    ports.append(PortInfo(ip=ip, port=int(port_str), service=""))
                except (ValueError, IndexError):
                    continue
        return ports
