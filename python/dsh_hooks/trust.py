#!/usr/bin/env python3
"""trust.py — hooks 配置信任三态（codex-parity-design.md M7，Phase C）

对齐 Codex config_rules 身份哈希语义：配置是数据，数据可能被篡改——
钩子以你的全部权限运行，所以「谁改了配置」必须可验证。

三态：
  trusted    指纹与上次显式确认一致 → 正常执行
  modified   有记录但指纹不符       → 拒绝自动执行（防篡改核心威胁），要求重新确认
  untracked  从未记录过             → 执行但打警告+审计标记（首装可用性优先）

用法：
  dsh-hooks check                 # 显示当前信任状态
  dsh-hooks trust                 # 显式确认当前配置（记录 sha256）
"""
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path


def _state_file() -> Path:
    root = Path(os.environ.get("DSH_HOME", os.path.expanduser("~/.dsh"))) / "hooks"
    return root / "trust.json"


def fingerprint(config_path: str) -> str:
    """配置内容 sha256（含路径一起指纹，移动文件视为变更）"""
    raw = Path(config_path).read_bytes()
    return hashlib.sha256(hashlib.sha256(raw).digest() + str(config_path).encode()).hexdigest()


def status_of(config_path: str) -> dict:
    fp = fingerprint(config_path)
    sf = _state_file()
    try:
        states = json.loads(sf.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        states = {}
    rec = states.get(str(config_path))
    if not rec:
        return {"state": "untracked", "fingerprint": fp}
    if rec.get("fingerprint") == fp:
        return {"state": "trusted", "fingerprint": fp,
                "trusted_at": rec.get("trusted_at")}
    return {"state": "modified", "fingerprint": fp,
            "last_trusted_at": rec.get("trusted_at"),
            "last_fingerprint": rec.get("fingerprint")}


def confirm(config_path: str) -> dict:
    """显式信任当前配置版本"""
    sf = _state_file()
    try:
        states = json.loads(sf.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        states = {}
    st = status_of(config_path)
    states[str(config_path)] = {
        "fingerprint": st["fingerprint"],
        "trusted_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    sf.parent.mkdir(parents=True, exist_ok=True)
    sf.write_text(json.dumps(states, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"state": "trusted", "fingerprint": st["fingerprint"], "path": config_path}


def enforce(config_path: str, require_trust: bool = False,
            audit_hook=None) -> dict:
    """加载期信任门。返回 {"allowed": bool, "status": {...}, "warning": str|None}

    - modified：require_trust=True 时拒绝；False 时也拒绝（防篡改是本模块的存在理由）
      —— modified 一律拒绝，唯一出路是 `dsh-hooks trust` 显式确认。
    - untracked：放行 + 警告（require_trust=True 时拒绝）。
    """
    st = status_of(config_path)
    if st["state"] == "trusted":
        return {"allowed": True, "status": st, "warning": None}
    if st["state"] == "modified":
        return {"allowed": False, "status": st,
                "warning": (f"hooks 配置自上次确认后已被修改（{config_path}）。"
                            f"钩子以你的全部用户权限运行，请检查改动后执行 "
                            f"`dsh-hooks trust --config {config_path}` 显式确认。")}
    # untracked
    if require_trust:
        return {"allowed": False, "status": st,
                "warning": (f"hooks 配置从未被信任确认（{config_path}）。"
                            f"执行 `dsh-hooks trust --config {config_path}` 后启用。")}
    return {"allowed": True, "status": st,
            "warning": f"hooks 配置尚未信任确认（untracked），建议 `dsh-hooks trust` 固化当前版本"}
