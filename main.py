#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.reporting import load_report, write_report

BANNER = r"""
  SCOUT
  Evidence-driven Security Assessment
"""


def normalize_target(raw: str) -> str:
    raw = raw.strip().strip("`'\"")
    if "://" in raw:
        parsed = urlparse(raw)
        raw = parsed.hostname or raw
    raw = raw.rstrip("/")
    raw = re.sub(r"^www\.", "", raw)
    return raw.lower()


def check_dependencies(stages: list[str] | None = None):
    from utils.logger import get_logger
    from utils.runner import check_tool_exists, BIN_DIR

    logger = get_logger("main")
    missing = []
    selected = set(stages or ["1", "2", "3", "4", "5"])
    required_tools = {
        "subfinder": ("2", "子域枚举"),
        "nuclei": ("5", "漏洞验证"),
        "httpx": ("3", "HTTP探测"),
        "nmap": ("3", "服务识别"),
    }
    optional_tools = {
        "rustscan": "高速端口扫描",
        "naabu": "端口扫描(备选)",
        "katana": "动态爬网",
        "feroxbuster": "目录爆破",
        "gitleaks": "凭据泄露扫描",
        "wappalyzer": "技术栈识别",
    }

    for tool, (stage_id, desc) in required_tools.items():
        if stage_id in selected and not check_tool_exists(tool):
            missing.append(f"  [必须] {tool} - {desc}")
    for tool, desc in optional_tools.items():
        if not check_tool_exists(tool):
            logger.info(f"可选工具未安装: {tool} ({desc})")

    if BIN_DIR.exists() and any(BIN_DIR.iterdir()):
        logger.info(f"bin/ 目录已启用 (工具路径: {BIN_DIR})")

    if missing:
        logger.error("以下必须工具未安装:")
        for m in missing:
            logger.error(m)
        logger.error("请先安装缺失工具后再运行")
        return False
    return True


async def main():
    parser = argparse.ArgumentParser(description="Scout - 红队自动化渗透 Agent")
    parser.add_argument("target", nargs="?", help="目标根域名，如 example.com")
    parser.add_argument("-c", "--config", default=None, help="配置文件路径 (默认: config/config.yaml)")
    parser.add_argument("-s", "--stages", default=None, help="指定执行阶段，逗号分隔，如 1,2,3 (默认: 全部)")
    ai_options = parser.add_mutually_exclusive_group()
    ai_options.add_argument("--ai", action="store_true", help="启用 AI 分析 (需配置 AI API Key)")
    ai_options.add_argument("--no-ai", action="store_true", help="禁用所有阶段内和报告 AI 调用")
    parser.add_argument("--linear", action="store_true", help="使用固定线性流水线，不启用 agentic 决策")
    parser.add_argument("--skip-check", action="store_true", help="跳过依赖检查")
    parser.add_argument("--list-stages", action="store_true", help="列出所有阶段")
    offline = parser.add_mutually_exclusive_group()
    offline.add_argument("--demo", action="store_true", help="使用合成数据演示，不执行扫描或 AI 调用")
    offline.add_argument("--report", help="离线分析已有 JSON/JSONL 报告，不执行扫描")
    parser.add_argument("--baseline", help="用于资产与发现对比的历史 JSON/JSONL 报告")
    parser.add_argument("-o", "--output-dir", help="报告输出目录")

    args = parser.parse_args()

    print(BANNER)

    if args.list_stages:
        for index, name in {1: "OSINT", 2: "边界拓展", 3: "指纹识别", 4: "内容探测", 5: "漏洞验证"}.items():
            print(f"  {index}: {name}")
        return

    if (args.demo or args.report) and (args.target or args.stages or args.ai):
        parser.error("离线模式不可与 target、--stages 或 --ai 同时使用")
    try:
        baseline = load_report(args.baseline) if args.baseline else None
        if args.demo or args.report:
            input_path = args.report or Path(__file__).parent / "examples" / "demo_report.json"
            report = load_report(input_path)
            paths = write_report(report, args.output_dir or "./output", baseline=baseline)
            print("离线分析完成，未执行扫描或 AI 调用。")
            for kind, path in paths.items():
                print(f"  {kind}: {path.resolve()}")
            return
    except (OSError, ValueError, TypeError, KeyError) as exc:
        parser.error(f"报告处理失败: {exc}")

    if not args.target:
        parser.error("需要目标域名，或使用 --demo / --report")
    stages = None
    if args.stages:
        stages = list(dict.fromkeys(s.strip() for s in args.stages.split(",")))
        if any(s not in {"1", "2", "3", "4", "5"} for s in stages):
            parser.error("阶段编号只能是 1-5")
        stages.sort(key=int)

    from core.config import Config
    from core.agent import ScoutAgent
    from utils.logger import get_logger

    logger = get_logger("main")
    target = normalize_target(args.target)
    if not target:
        parser.error("目标不可为空")
    if baseline and baseline["target"].strip().lower().rstrip(".") != target:
        parser.error("历史报告的 target 必须与本次目标一致")

    config = Config(args.config)
    output_format = config.get("output", "format", default="jsonl")
    if output_format not in {"json", "jsonl"}:
        parser.error("output.format 只支持 json 或 jsonl")
    if args.no_ai:
        config.raw.setdefault("ai", {})["api_key"] = ""
    agent = ScoutAgent(config)

    if not args.skip_check:
        if not check_dependencies(stages):
            sys.exit(1)

    if target != args.target:
        logger.info(f"目标已标准化: {args.target} -> {target}")

    logger.info(f"目标: {target}")
    logger.info(f"阶段: {stages or '全部(1-5)'}")
    ai_key_set = bool(config.get("ai", "api_key"))
    enable_ai = (args.ai or ai_key_set) and not args.no_ai
    enable_agentic = enable_ai and not args.linear
    logger.info(f"AI 分析: {'启用' if enable_ai else '禁用'}")
    logger.info(f"Agentic 决策: {'启用' if enable_agentic else '禁用'}")

    if enable_agentic:
        ctx = await agent.run_agentic(target, stages=stages, persist=False)
    elif enable_ai:
        ctx = await agent.run_with_ai(target, stages=stages, persist=False)
    else:
        ctx = await agent.run(target, stages=stages, persist=False)

    output_dir = args.output_dir or config.get("output", "dir", default="./output")
    paths = write_report(
        ctx.to_final_report(), output_dir, baseline=baseline,
        fmt=output_format,
    )
    for kind, path in paths.items():
        logger.info(f"{kind} 报告已保存: {path.resolve()}")


if __name__ == "__main__":
    asyncio.run(main())
