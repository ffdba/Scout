from __future__ import annotations

import asyncio
from typing import Type

from core.config import Config
from core.models import PipelineContext, StageResult
from core.stage import BaseStage
from utils.logger import get_logger

logger = get_logger("pipeline")


class Pipeline:
    def __init__(self, config: Config):
        self.config = config
        self.stages: list[BaseStage] = []
        self.ctx = PipelineContext()

    def register(self, stage_cls: Type[BaseStage]) -> Pipeline:
        stage = stage_cls(self.config)
        self.stages.append(stage)
        return self

    async def execute(self, target: str, *, persist: bool = True) -> PipelineContext:
        self.ctx = PipelineContext(target=target)
        logger.info(f"开始对目标 {target} 执行 {len(self.stages)} 个阶段")

        for stage in self.stages:
            stage.logger.info(f"阶段 {stage.index}: {stage.name} 启动")
            try:
                result: StageResult = await stage.run(self.ctx)
                self.ctx.merge(result)
                stage._log_done(result)
            except Exception as e:
                logger.error(f"阶段 {stage.index} ({stage.name}) 异常: {e}")
                err_result = StageResult(
                    stage_name=stage.name,
                    stage_index=stage.index,
                    errors=[str(e)],
                )
                self.ctx.merge(err_result)

        if persist:
            self._save_output()
        return self.ctx

    def _save_output(self):
        output_dir = self.config.get("output", "dir", default="./output")
        fmt = self.config.get("output", "format", default="jsonl")
        from core.reporting import write_report
        paths = write_report(self.ctx.to_final_report(), output_dir, fmt=fmt)
        logger.info(f"报告已保存: {paths['json']}")
