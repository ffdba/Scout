#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.config import Config
from core.agent import RedAgent
from utils.logger import get_logger

logger = get_logger("main")

BANNER = r"""
  ╦═╗┌─┐┬  ┬┌─┐┌┐┌  ╔╗╔┌─┐─┐ ┬┬ ┬┌─┐
  ╠╦╝├─┤└┐┌┘├┤ │││  ║║║├┤ ┌┴┬┘│ │└─┐
  ╩╚═┴ ┴ └┘ └─┘┘└┘  ╝╚╝└─┘┴ └─└─┘└─┘
  Red Team Automated Penetration Agent v1.0
"""


def check_dependencies():
    missing = []
    required_tools = {
        "subfinder": "子域枚举",
        "nuclei": "漏洞验证",
        "httpx": "HTTP探测",
        "nmap": "服务识别",
    }
    optional_tools = {
        "rustscan": "高速端口扫描",
        "naabu": "端口扫描(备选)",
        "katana": "动态爬网",
        "feroxbuster": "目录爆破",
        "gitleaks": "凭据泄露扫描",
        "wappalyzer": "技术栈识别",
    }

    import shutil
    for tool, desc in required_tools.items():
        if not shutil.which(tool):
            missing.append(f"  [必须] {tool} - {desc}")
    for tool, desc in optional_tools.items():
        if not shutil.which(tool):
            logger.info(f"可选工具未安装: {tool} ({desc})")

    if missing:
        logger.error("以下必须工具未安装:")
        for m in missing:
            logger.error(m)
        logger.error("请先安装缺失工具后再运行")
        return False
    return True


async def main():
    parser = argparse.ArgumentParser(description="RedAgent - 红队自动化渗透 Agent")
    parser.add_argument("target", help="目标根域名，如 example.com")
    parser.add_argument("-c", "--config", default=None, help="配置文件路径 (默认: config/config.yaml)")
    parser.add_argument("-s", "--stages", default=None, help="指定执行阶段，逗号分隔，如 1,2,3 (默认: 全部)")
    parser.add_argument("--ai", action="store_true", help="启用 AI 分析 (需配置 AI API Key)")
    parser.add_argument("--skip-check", action="store_true", help="跳过依赖检查")
    parser.add_argument("--list-stages", action="store_true", help="列出所有阶段")

    args = parser.parse_args()

    print(BANNER)

    config = Config(args.config)

    agent = RedAgent(config)

    if args.list_stages:
        print("可用阶段:")
        for key, cls in RedAgent.STAGE_MAP.items():
            print(f"  {key}: {cls.name if hasattr(cls, 'name') else cls.__name__}")
        return

    if not args.skip_check:
        if not check_dependencies():
            sys.exit(1)

    stages = None
    if args.stages:
        stages = [s.strip() for s in args.stages.split(",")]

    logger.info(f"目标: {args.target}")
    logger.info(f"阶段: {stages or '全部(1-5)'}")
    logger.info(f"AI 分析: {'启用' if args.ai else '禁用'}")

    if args.ai:
        ctx = await agent.run_with_ai(args.target, stages=stages)
    else:
        ctx = await agent.run(args.target, stages=stages)

    output_dir = config.get("output", "dir", default="./output")
    target_safe = args.target.replace(".", "_").replace("/", "_")
    report_path = Path(output_dir) / f"{target_safe}_report.json"
    ctx.save_json(str(report_path))
    logger.info(f"完整报告已保存: {report_path}")


if __name__ == "__main__":
    asyncio.run(main())
