from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from core.config import Config
from core.models import PortInfo
from utils.logger import get_logger
from utils.runner import run_async, check_tool_exists

logger = get_logger("nmap")


class NmapTool:
    def __init__(self, config: Config):
        self.config = config
        self.timeout = config.get("nmap", "timeout", default=600)
        self.service_detection = config.get("nmap", "service_detection", default=True)
        self.os_detection = config.get("nmap", "os_detection", default=False)
        self.scripts = config.get("nmap", "scripts", default="default,vuln")

    async def scan(self, targets: list[str], ports: list[int] | None = None) -> list[PortInfo]:
        if not check_tool_exists("nmap"):
            logger.warning("nmap 未安装，跳过服务识别")
            return []

        all_ports: list[PortInfo] = []
        for target in targets:
            logger.info(f"Nmap 扫描: {target}")
            cmd = ["nmap"]

            if ports:
                cmd.extend(["-p", ",".join(str(p) for p in ports)])

            if self.service_detection:
                cmd.append("-sV")
            if self.os_detection:
                cmd.append("-O")
            if self.scripts:
                cmd.extend([f"--script={self.scripts}"])

            cmd.extend(["-oX", "-", target])

            result = await run_async(cmd, timeout=self.timeout)
            if result.success:
                all_ports.extend(self._parse_xml(result.stdout))

        logger.info(f"Nmap 共识别 {len(all_ports)} 个服务")
        return all_ports

    def _parse_xml(self, xml_output: str) -> list[PortInfo]:
        ports: list[PortInfo] = []
        try:
            root = ET.fromstring(xml_output)
            for host in root.findall("host"):
                address = host.find("address")
                ip = address.get("addr", "") if address is not None else ""
                ports_elem = host.find("ports")
                if ports_elem is None:
                    continue
                for port in ports_elem.findall("port"):
                    state = port.find("state")
                    if state is not None and state.get("state") != "open":
                        continue
                    service = port.find("service")
                    ports.append(PortInfo(
                        ip=ip,
                        port=int(port.get("portid", 0)),
                        protocol=port.get("protocol", "tcp"),
                        service=service.get("name", "") if service is not None else "",
                        version=service.get("version", "") if service is not None else "",
                        product=service.get("product", "") if service is not None else "",
                    ))
        except ET.ParseError as e:
            logger.error(f"Nmap XML 解析失败: {e}")
        return ports
