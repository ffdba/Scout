from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime

from core.config import Config
from core.models import PipelineContext, StageResult
from utils.logger import get_logger


class BaseStage(ABC):
    name: str = ""
    index: int = 0

    def __init__(self, config: Config):
        self.config = config
        self.logger = get_logger(f"stage{self.index}")
        self._thoughts: list[dict] = []

    @abstractmethod
    async def run(self, ctx: PipelineContext) -> StageResult:
        ...

    async def think(self, ctx: PipelineContext) -> str:
        prompt = self._build_think_prompt(ctx)
        ai_key = self.config.get("ai", "api_key")
        if not ai_key:
            thought = self._local_think(ctx)
            self._output_thought(thought, source="rule")
            return thought

        try:
            from openai import AsyncOpenAI
            base_url = self.config.get("ai", "base_url", default="https://api.openai.com/v1")
            model = self.config.get("ai", "model", default="gpt-4o")
            client = AsyncOpenAI(api_key=ai_key, base_url=base_url)
            resp = await client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "你是一名红队渗透测试专家，正在分析当前渗透阶段的策略。请用简洁的中文输出你的思考过程，包括：1)当前情报摘要 2)攻击面评估 3)本阶段策略 4)预期产出"},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.3,
                max_tokens=1024,
            )
            thought = resp.choices[0].message.content or ""
            self._output_thought(thought, source="ai")
            return thought
        except Exception as e:
            self.logger.warning(f"AI 思考失败，回退到规则推理: {e}")
            thought = self._local_think(ctx)
            self._output_thought(thought, source="rule")
            return thought

    def _build_think_prompt(self, ctx: PipelineContext) -> str:
        lines = [
            f"目标: {ctx.target}",
            f"当前阶段: 阶段{self.index} - {self.name}",
            f"已发现子域数: {len(ctx.all_subdomains)}",
            f"已发现端口数: {len(ctx.all_ports)}",
            f"已发现指纹数: {len(ctx.all_fingerprints)}",
            f"已发现敏感路径数: {len(ctx.all_sensitive_paths)}",
            f"已发现漏洞数: {len(ctx.all_vulnerabilities)}",
            f"已发现凭据泄露数: {len(ctx.all_credential_leaks)}",
        ]
        if ctx.all_subdomains:
            sample = [s.domain for s in ctx.all_subdomains[:5]]
            lines.append(f"子域样本: {', '.join(sample)}")
        if ctx.all_ports:
            sample = [f"{p.ip}:{p.port}" for p in ctx.all_ports[:5]]
            lines.append(f"端口样本: {', '.join(sample)}")
        if ctx.all_fingerprints:
            sample = [f.url for f in ctx.all_fingerprints[:3]]
            lines.append(f"存活URL样本: {', '.join(sample)}")
        return "\n".join(lines)

    def _local_think(self, ctx: PipelineContext) -> str:
        parts = []
        if self.index == 1:
            parts.append(f"[情报摘要] 目标 {ctx.target}，尚无历史数据")
            parts.append("[攻击面评估] 从零开始被动侦察，需最大化信息收集覆盖面")
            parts.append("[策略] 并行调用 crt.sh/Quake/Hunter 获取历史子域与源站IP，Gitleaks扫描凭据泄露")
            parts.append("[预期] 获取历史子域列表、潜在源站IP、泄露凭据")
        elif self.index == 2:
            parts.append(f"[情报摘要] 已有 {len(ctx.all_subdomains)} 个子域")
            parts.append("[攻击面评估] 需补充主动枚举子域并探测存活端口")
            parts.append("[策略] Subfinder主动枚举补充OSINT结果，RustScan/Naabu高速端口扫描")
            parts.append("[预期] 当前存活子域列表、开放端口清单")
        elif self.index == 3:
            parts.append(f"[情报摘要] {len(ctx.all_subdomains)} 个子域, {len(ctx.all_ports)} 个开放端口")
            parts.append("[攻击面评估] 已有存活资产清单，需精准识别服务与中间件")
            parts.append("[策略] Nmap定向服务识别(仅扫已发现端口)，Httpx批量HTTP探测，Wappalyzer深度技术栈识别")
            parts.append("[预期] 操作系统/中间件/CMS指纹，标准JSON格式画像")
        elif self.index == 4:
            parts.append(f"[情报摘要] {len(ctx.all_fingerprints)} 个存活目标")
            parts.append("[攻击面评估] 已有技术栈画像，需深挖敏感路径与隐藏入口")
            parts.append("[策略] Katana动态爬网发现输入点，Feroxbuster字典爆破备份/配置文件")
            parts.append("[预期] 敏感输入点、备份文件、异常响应路径")
        elif self.index == 5:
            parts.append(f"[情报摘要] {len(ctx.all_fingerprints)} 个指纹, {len(ctx.all_sensitive_paths)} 个路径")
            parts.append("[攻击面评估] 已有完整攻击面画像，进入精准漏洞验证")
            parts.append("[策略] Agent标签路由根据技术栈匹配Nuclei模板标签，Nuclei执行原子化验证")
            parts.append("[预期] 已验证漏洞列表，按严重级别分类")
        return "\n".join(parts)

    def _output_thought(self, thought: str, source: str = "rule"):
        ts = datetime.now().strftime("%H:%M:%S")
        label = "AI" if source == "ai" else "规则"
        self._thoughts.append({"source": source, "thought": thought, "timestamp": ts})
        print()
        print(f"\033[36m{'─'*60}\033[0m")
        print(f"\033[36m🧠 Agent 思考 [阶段{self.index}: {self.name}] [{label}] [{ts}]\033[0m")
        print(f"\033[36m{'─'*60}\033[0m")
        for line in thought.strip().splitlines():
            print(f"\033[36m  {line}\033[0m")
        print(f"\033[36m{'─'*60}\033[0m")
        print()

    def think_step(self, message: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self._thoughts.append({"source": "step", "thought": message, "timestamp": ts})
        print(f"\033[33m  ⚡ [{ts}] {message}\033[0m")

    def _make_result(self) -> StageResult:
        result = StageResult(stage_name=self.name, stage_index=self.index)
        result.raw_data["agent_thoughts"] = self._thoughts
        return result

    def _log_start(self, target: str):
        self.logger.info(f"{'='*60}")
        self.logger.info(f"阶段 {self.index}: {self.name} | 目标: {target}")
        self.logger.info(f"{'='*60}")

    def _log_done(self, result: StageResult):
        counts = {
            "子域": len(result.subdomains),
            "端口": len(result.ports),
            "指纹": len(result.fingerprints),
            "敏感路径": len(result.sensitive_paths),
            "漏洞": len(result.vulnerabilities),
            "凭据泄露": len(result.credential_leaks),
        }
        summary = " | ".join(f"{k}={v}" for k, v in counts.items() if v > 0)
        self.logger.info(f"阶段 {self.index} 完成: {summary or '无新发现'}")
