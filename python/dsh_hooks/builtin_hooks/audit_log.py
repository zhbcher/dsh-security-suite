#!/usr/bin/env python3
"""内置钩子：审计日志（可挂任意事件）

把每次事件的完整信封追加到 $DSH_HOME/hooks/audit.jsonl（一行一条 JSON），
供事后审计与回放。永远放行，永不阻断主流程。
"""
import json
import os
import sys
from datetime import datetime
from pathlib import Path


def main():
    payload = json.load(sys.stdin)
    root = Path(os.environ.get("DSH_HOME", os.path.expanduser("~/.dsh"))) / "hooks"
    root.mkdir(parents=True, exist_ok=True)
    record = {
        "time": datetime.now().isoformat(timespec="seconds"),
        "event": payload.get("event"),
        "session": (payload.get("session") or {}).get("id"),
        "tool": (payload.get("data") or {}).get("tool_name"),
        "command": str((payload.get("data") or {}).get("tool_input", {})
                       .get("command", ""))[:300],
    }
    with open(root / "audit.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    json.dump({}, sys.stdout)          # 放行


if __name__ == "__main__":
    sys.exit(main())
