#!/usr/bin/env python3
"""config.py — hooks.json 加载 / 校验 / builtin: 命令解析"""
import json
import logging
import os
import shlex
from pathlib import Path
from typing import List

log = logging.getLogger("dsh-hooks")

PKG_ROOT = Path(__file__).resolve().parent          # = dsh_hooks 包目录


def default_config_path() -> Path:
    dsh_home = Path(os.environ.get("DSH_HOME", os.path.expanduser("~/.dsh")))
    return dsh_home / "hooks.json"


def _expand_tokens(command: str) -> list:
    """'~/x.py --flag v' → ['/Users/…/x.py','--flag','v']；builtin:name → 解释器+脚本路径"""
    if command.startswith("builtin:"):
        script = PKG_ROOT / "builtin_hooks" / f"{command[len('builtin:'):].strip()}.py"
        return [__import__("sys").executable, str(script)]
    parts = shlex.split(command)
    return [os.path.expanduser(p) if p.startswith("~") else p for p in parts]


def load_config(path: str = None) -> List[dict]:
    """加载并校验 hooks.json，展开为扁平的 handler 规格列表。

    文件结构：
      {"hooks": {"PreToolUse": [{"name","matcher","command","timeout_s","priority"}, …]}}
    返回条目含 "_source"（文件来源）便于审计。
    """
    cfg_path = Path(path) if path else default_config_path()
    if not cfg_path.exists():
        log.info("未找到配置 %s，钩子总线为空", cfg_path)
        return []
    raw = json.loads(cfg_path.read_text(encoding="utf-8"))
    hooks = raw.get("hooks") or {}
    specs: List[dict] = []
    for event, entries in hooks.items():
        if not isinstance(entries, list):
            raise ValueError(f"{cfg_path}: 事件 {event} 的值必须是数组")
        for i, entry in enumerate(entries):
            if not isinstance(entry, dict) or not entry.get("command"):
                raise ValueError(f"{cfg_path}: {event}[{i}] 缺少 command 字段")
            spec = {
                "event": event,
                "command": entry["command"],
                "name": entry.get("name", ""),
                "matcher": entry.get("matcher"),
                "priority": entry.get("priority", 100),
                "timeout_s": entry.get("timeout_s", 10),
                "_source": str(cfg_path),
            }
            # 提前解析命令（builtin 展开 / ~ 展开），坏配置立刻报错
            resolve_command(spec["command"])
            specs.append(spec)
    return specs


def load_options(path: str = None) -> dict:
    """读取 hooks.json 顶层 options（Phase C M6/M7/M8）：
    concurrency / require_trust / env_passthrough。文件不存在返回空 dict。"""
    cfg_path = Path(path) if path else default_config_path()
    if not cfg_path.exists():
        return {}
    try:
        raw = json.loads(cfg_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    opts = raw.get("options") or {}
    return {
        "concurrency": bool(opts.get("concurrency", False)),
        "require_trust": bool(opts.get("require_trust", False)),
        "env_passthrough": [str(x) for x in opts.get("env_passthrough", [])],
        "_path": str(cfg_path),
    }


# 延迟导入避免循环依赖：bus 需要 resolve_command，config 不需要 bus
def resolve_command(command: str) -> list:
    return _expand_tokens(command)
