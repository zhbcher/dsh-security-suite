#!/usr/bin/env python3
"""protocol.py — 子进程钩子的调用契约

契约：
  stdin  ← 完整 JSON 信封 {"event","time","session","data"}
  stdout → JSON outcome（可选）：
             {}                                        放行
             {"decision":"deny","reason":"..."}         拦截
             {"decision":"rewrite","data":{...}}        改写
             {"data":{...}}                             同 rewrite
  exit   → 0 正常（看 stdout）| 2 拦截（stderr=理由）| 其他 = 非致命错误（放行并记录）
"""
import json
import logging
import os
import subprocess
from datetime import datetime
from pathlib import Path

log = logging.getLogger("dsh-hooks")

# ── M8: env 白名单清洗（Codex「env 快照 scrub 凭据」语义）───────────────────
# 第三方钩子以你的全部权限运行，绝不能顺手继承含密钥的环境变量。
ENV_ALLOWLIST = {
    "PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP",
    "USER", "SHELL", "TERM", "PWD",
    "DSH_HOME", "DSH_PERMISSION_MODE", "DSH_WORK_DIR",
}
ENV_ALLOW_PREFIX = ("DSH_HOOKS_",)          # 本体系变量按前缀放行


def sanitize_env(extra_passthrough=None) -> dict:
    """白名单过滤当前环境；extra_passthrough 来自 hooks.json 顶层 env_passthrough"""
    allow = set(ENV_ALLOWLIST) | set(extra_passthrough or ())
    return {k: v for k, v in os.environ.items()
            if k in allow or k.startswith(ENV_ALLOW_PREFIX)}


# ── M11: 超长输出落盘（Codex additionalContext >2500 token spill 语义）──────
SPILL_THRESHOLD = 10_000                    # 字符
SPILL_KEEP_HEAD = 400                       # 替换文本保留的头部


def _write_spill(text: str, name: str) -> str:
    d = Path(os.environ.get("DSH_HOME", os.path.expanduser("~/.dsh"))) / "hooks" / "spill"
    d.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in name)[:60]
    p = d / f"{ts}-{safe}.txt"
    p.write_text(text, encoding="utf-8")
    return str(p)


def spill_if_huge(outcome: dict, hook_name: str) -> dict:
    """message/data 中超长字符串值落盘 ~/.dsh/hooks/spill/，正文替换为引用"""
    try:
        msg = outcome.get("message")
        if isinstance(msg, str) and len(msg) > SPILL_THRESHOLD:
            path = _write_spill(msg, hook_name)
            outcome["message"] = (f"[超长输出已落盘 {path}] "
                                  + msg[:SPILL_KEEP_HEAD] + " …")
        data = outcome.get("data")
        if isinstance(data, dict):
            for k, v in list(data.items()):
                if isinstance(v, str) and len(v) > SPILL_THRESHOLD:
                    path = _write_spill(v, f"{hook_name}.{k}")
                    data[k] = f"[超长输出已落盘 {path}]"
    except OSError as e:                     # 落盘失败不影响钩子语义
        log.warning("spill 落盘失败(忽略): %s", e)
    return outcome


def run_subprocess(command: list, payload: dict,
                   timeout_s: int = 10, env_passthrough=None) -> dict:
    """执行一个子进程钩子，返回规范化 outcome。永不抛异常（容错语义）。"""
    try:
        proc = subprocess.run(
            command,
            input=json.dumps(payload, ensure_ascii=False),
            capture_output=True, text=True,
            timeout=timeout_s,
            env=sanitize_env(env_passthrough),   # M8: 白名单 env，防凭据外泄给第三方钩子
        )
    except subprocess.TimeoutExpired:
        log.warning("钩子超时(>%ss)，按放行处理: %s", timeout_s, command)
        return {"action": "pass", "message": f"timeout>{timeout_s}s"}
    except FileNotFoundError as e:
        log.warning("钩子命令不存在(非致命): %s (%s)", command, e)
        return {"action": "pass", "message": f"command not found: {e}"}

    stderr = (proc.stderr or "").strip()

    # 解释器级错误的 exit 2 不是业务拦截，按非致命处理
    INTERPRETER_ERRORS = ("can't open file", "SyntaxError",
                          "ModuleNotFoundError", "No module named")
    if proc.returncode == 2 and any(s in stderr for s in INTERPRETER_ERRORS):
        log.warning("钩子自身异常(rc=2 非致命): %s", stderr[:200])
        return {"action": "pass", "message": f"hook crashed: {stderr[:120]}"}

    if proc.returncode == 2:
        return {"action": "deny",
                "reason": stderr or "被钩子拦截（exit 2）"}

    if proc.returncode != 0:
        log.warning("钩子异常退出 rc=%s(非致命): %s", proc.returncode, stderr[:200])
        return {"action": "pass", "message": f"rc={proc.returncode}"}

    stdout = (proc.stdout or "").strip()
    if not stdout:
        return {"action": "pass"}

    try:
        out = json.loads(stdout)
    except json.JSONDecodeError:
        return {"action": "pass", "message": f"non-json stdout: {stdout[:120]}"}

    normalized = normalize_outcome(out)
    if stderr:                       # 钩子可能用 stderr 附带说明
        normalized.setdefault("message", stderr[:200])
    return spill_if_huge(normalized, command[-1] if command else "hook")


def normalize_outcome(outcome) -> dict:
    """与 bus.normalize_outcome 一致；此处独立实现避免循环导入。"""
    if outcome is None:
        return {"action": "pass"}
    if not isinstance(outcome, dict):
        return {"action": "pass"}
    decision = str(outcome.get("decision", "")).lower()
    if decision in ("deny", "block", "blocked"):
        return {"action": "deny",
                "reason": outcome.get("reason") or "被钩子拦截"}
    if isinstance(outcome.get("data"), dict):
        return {"action": "rewrite", "data": outcome["data"]}
    return {"action": "pass"}
