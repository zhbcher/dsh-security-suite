"""dsh-hooks — Agent 生命周期钩子总线

六个生命周期事件（对齐 OpenAI Codex 设计）：
    SessionStart / UserPromptSubmit / PreToolUse /
    PostToolUse / PreCompact / SessionEnd

两种用法：
    进程内:  from dsh_hooks import HookBus
             bus = HookBus.from_config()
             r = bus.emit("PreToolUse", {"tool_name": "Bash", "tool_input": {...}})
    子进程:  echo '{"tool_name":"Bash",...}' | dsh-hooks emit PreToolUse
             （exit 0 = 放行；exit 2 = 拦截）
"""
from .bus import HookBus, EmitResult, FuncHandler, CommandHandler, EVENTS
from .config import load_config, default_config_path

__version__ = "0.1.0"
__all__ = [
    "HookBus", "EmitResult", "FuncHandler", "CommandHandler",
    "EVENTS", "load_config", "default_config_path", "__version__",
]
