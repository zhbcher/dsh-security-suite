#!/usr/bin/env python3
"""bus.py — 事件总线核心：注册、匹配、短路、链式改写"""
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from . import protocol
from .config import load_config, resolve_command

log = logging.getLogger("dsh-hooks")

EVENTS = ["SessionStart", "UserPromptSubmit", "PreToolUse",
          "PostToolUse", "PreCompact", "SessionEnd", "ReplyReady", "Stop"]
# ReplyReady = Agent 回复交给用户前的最后一道出口检查（防凭据/隐私外泄）
# Stop = Agent 回合结束事件（M10：block 时回注提示；stop_hook_active 防死循环
#        由调用方负责——连续两次 Stop block 必须放行，与 Codex/Claude 语义一致）
# matcher 只对工具类事件有意义（对齐 Codex：其余事件的 matcher 字段被忽略）
MATCHER_APPLICABLE = {"PreToolUse", "PostToolUse"}


@dataclass
class EmitResult:
    """emit() 的返回结果。"""
    allowed: bool = True
    reason: Optional[str] = None
    data: dict = field(default_factory=dict)
    trace: List[dict] = field(default_factory=list)   # 每个钩子干了什么（审计用）

    def __bool__(self):            # if result: 放行了
        return self.allowed


class Handler:
    """钩子的统一抽象。"""

    def __init__(self, event: str, name: str = "", matcher: str = None,
                 priority: int = 100, timeout_s: int = 10, source: str = ""):
        self.event = event
        self.name = name or source
        self.matcher = re.compile(matcher) if matcher else None
        self.priority = priority
        self.timeout_s = timeout_s
        self.source = source

    def matches(self, event: str, payload: dict) -> bool:
        if self.event != event:
            return False
        if self.matcher and event in MATCHER_APPLICABLE:
            tool_name = (payload.get("data") or {}).get("tool_name", "")
            if not self.matcher.search(str(tool_name)):
                return False
        return True

    def run(self, payload: dict) -> dict:
        raise NotImplementedError


class FuncHandler(Handler):
    """进程内 Python 函数钩子：fn(payload_dict) -> outcome_dict|None"""

    def __init__(self, fn: Callable, event: str, **kw):
        super().__init__(event=event, name=kw.pop("name", getattr(fn, "__name__", "")), **kw)
        self.fn = fn

    def run(self, payload: dict) -> dict:
        out = self.fn(payload)
        return protocol.normalize_outcome(out)


class CommandHandler(Handler):
    """外部命令钩子（stdin/stdout JSON 契约）。command 支持 builtin: 简写与 ~ 展开。"""

    def __init__(self, command: str, **kw):
        super().__init__(**kw)
        self.command = resolve_command(command)

    def run(self, payload: dict) -> dict:
        return protocol.run_subprocess(self.command, payload,
                                       timeout_s=self.timeout_s,
                                       env_passthrough=getattr(self, "_env_pt", None))


class HookBus:
    def __init__(self, concurrent: bool = False,
                 env_passthrough: list = None):
        self._handlers: List[Handler] = []
        self._seq = 0
        # M6: 同优先级层并发执行 + any-deny 聚合（默认关闭保持链式改写语义）
        self.concurrent = concurrent
        # M8: 透传给子进程钩子的额外环境变量白名单
        self.env_passthrough = env_passthrough or []

    # ── 注册 ──
    def register(self, handler: Handler) -> Handler:
        self._seq += 1
        handler._seq = self._seq
        if handler.event not in EVENTS:
            raise ValueError(f"未知事件 {handler.event!r}，可选: {EVENTS}")
        handler._env_pt = self.env_passthrough
        self._handlers.append(handler)
        return handler

    def add_func(self, event: str, fn: Callable, **kw) -> FuncHandler:
        return self.register(FuncHandler(fn, event, **kw))

    @classmethod
    def from_config(cls, path: str = None) -> "HookBus":
        """从 hooks.json 构建总线（默认 $DSH_HOME/hooks.json 或 ~/.dsh/hooks.json）。"""
        from .config import load_options
        opts = load_options(path)
        bus = cls(concurrent=opts.get("concurrency", False),
                  env_passthrough=opts.get("env_passthrough", []))
        for spec in load_config(path):
            bus.register(CommandHandler(
                command=spec["command"],
                event=spec["event"],
                name=spec.get("name", ""),
                matcher=spec.get("matcher"),
                priority=int(spec.get("priority", 100)),
                timeout_s=int(spec.get("timeout_s", 10)),
                source=spec.get("_source", ""),
            ))
        return bus

    # ── 分发 ──
    def emit(self, event: str, data: dict,
             session: dict = None) -> EmitResult:
        if event not in EVENTS:
            raise ValueError(f"未知事件 {event!r}，可选: {EVENTS}")
        payload = {"event": event, "time": int(time.time() * 1000),
                   "session": session or {}, "data": data}

        handlers = sorted((h for h in self._handlers
                           if h.matches(event, payload)),
                          key=lambda h: (h.priority, h._seq))
        if self.concurrent and len(handlers) > 1:
            return self._emit_concurrent(event, payload, handlers)
        return self._emit_serial(event, payload, handlers)

    @staticmethod
    def _safe_run(h: Handler, payload: dict) -> dict:
        try:
            return h.run(payload)
        except Exception as e:                     # 钩子崩溃不拖死主流程
            log.exception("钩子 %s 异常(非致命)", h.name)
            return {"action": "error", "message": str(e)[:200]}

    def _emit_concurrent(self, event, payload, handlers) -> EmitResult:
        """M6 并发模式（对齐 Codex hooks engine）：同优先级层并发执行、按配置序
        重排聚合；any-deny-wins。注意：rewrite 在并发下无法保证链式顺序，
        只应用该层中优先级最高的第一个 rewrite（文档语义，勿依赖并发改写链）。"""
        from concurrent.futures import ThreadPoolExecutor
        trace: List[dict] = []
        layers: List[List[Handler]] = []
        for h in handlers:                         # handlers 已按 (priority,_seq) 排序
            if not layers or layers[-1][0].priority != h.priority:
                layers.append([h])
            else:
                layers[-1].append(h)

        for layer in layers:
            with ThreadPoolExecutor(max_workers=min(8, len(layer))) as ex:
                outcomes = list(ex.map(lambda h: self._safe_run(h, payload), layer))

            denies = [(h, o) for h, o in zip(layer, outcomes)
                      if o.get("action") == "deny"]
            for h, o in zip(layer, outcomes):      # trace 按配置序重排
                entry = {"hook": h.name or h.source, "action": o.get("action", "pass")}
                if o.get("reason"):
                    entry["reason"] = o["reason"]
                if o.get("message"):
                    entry["message"] = o["message"]
                trace.append(entry)
            if denies:
                reasons = list(dict.fromkeys(
                    o.get("reason") or f"被 {h.name or '钩子'} 拦截"
                    for h, o in denies))           # 去重保序
                log.info("事件 %s 被 %d 个钩子拦截(并发)", event, len(denies))
                return EmitResult(False, "；".join(reasons), payload["data"], trace)

            for h, o in zip(layer, outcomes):      # rewrite 取最高优先级的一个
                if o.get("action") == "rewrite":
                    payload["data"] = o["data"]
                    trace.append({"hook": h.name or h.source,
                                  "action": "rewrite", "rewritten": True})
                    break
        return EmitResult(True, None, payload["data"], trace)

    def _emit_serial(self, event, payload, handlers) -> EmitResult:
        trace = []
        for h in handlers:
            out = self._safe_run(h, payload)

            action = out.get("action", "pass")
            entry = {"hook": h.name or h.source, "action": action}
            if out.get("message"):
                entry["message"] = out["message"]

            if action == "error":
                trace.append(entry)
                continue

            if action == "deny":
                entry["reason"] = out.get("reason")
                trace.append(entry)
                log.info("事件 %s 被 %s 拦截: %s",
                         event, h.name, out.get("reason"))
                return EmitResult(False, out.get("reason"),
                                  payload["data"], trace)
            if action == "rewrite":
                payload["data"] = out["data"]           # 链式改写传给下一棒
                entry["rewritten"] = True
            trace.append(entry)

        return EmitResult(True, None, payload["data"], trace)

    def describe(self) -> list:
        """列出已注册的钩子（check 子命令用）。"""
        return [{"event": h.event, "name": h.name, "matcher":
                 (h.matcher.pattern if h.matcher else None),
                 "priority": h.priority, "timeout_s": h.timeout_s,
                 "source": h.source}
                for h in sorted(self._handlers,
                                key=lambda h: (h.event, h.priority, h._seq))]
