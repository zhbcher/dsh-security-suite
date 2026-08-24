#!/usr/bin/env python3
"""内置钩子：秘密文件访问守卫（挂 PreToolUse，matcher 建议 Bash|Shell|Python|zsh）

拦截"读取/打包/外传已知秘密文件"的命令组合：
  ① 命令中出现已知秘密文件的路径或其特征名（.proxy-token / .credentials.yaml /
     cordis.patch.yml / public-web-sessions.json 等）
  ② 且伴随外泄放大动作：压缩打包(zip/tar/gz)、编码(base64/gpg)、复制到家目录外、
     网络发送(curl/wget/scp/lark-cli/邮件)

命中即 deny 并给出理由。注意这是提高攻击成本的纵深防御层：
同用户进程原则上总能读到同用户文件，根治要靠沙箱与最小权限。
"""
import json
import os
import re
import sys
from pathlib import Path

HOME = os.path.expanduser("~")
DSH_HOME = os.environ.get("DSH_HOME", os.path.expanduser("~/.dsh"))

# 已知秘密文件的特征（路径片段，命中即视为触碰秘密）
SECRET_PATH_SIGNS = [
    ".proxy-token",
    ".credentials.yaml",
    "cordis.patch.yml",          # web 登录密码明文所在
    "public-web-sessions.json",
    "settings.yaml.bak",
]

# 外泄放大动作：通用工具 + 各聊天渠道二进制名（从 hooks-egress.json 动态读取，
# 接入新渠道只需在出口配置里加一行，这里的拦截自动覆盖）
try:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
    from dsh_hooks.egress import channel_name_pattern
    _channel_pattern = channel_name_pattern()
except Exception:                                   # 独立运行时的兜底
    _channel_pattern = r"lark-cli"

EXFIL_SIGNS = [
    r"\b(zip|gzip|tar|7z|base64|gpg|openssl)\b",
    r"\b(cp|mv|rsync|scp|sftp)\b",
    rf"\b({_channel_pattern})\b",
    r"\bmail(x)?\b",
]


def main():
    payload = json.load(sys.stdin)
    data = payload.get("data") or {}
    tool = str(data.get("tool_name", "")).lower()
    if tool not in ("bash", "shell", "python", "zsh"):
        json.dump({}, sys.stdout)
        return
    command = str((data.get("tool_input") or {}).get("command", ""))
    if not command:
        json.dump({}, sys.stdout)
        return

    touches = [s for s in SECRET_PATH_SIGNS if s in command]
    if not touches:
        json.dump({}, sys.stdout)          # 没碰秘密文件，放行
        return

    exfil = [p for p in EXFIL_SIGNS if re.search(p, command)]
    # 只读查看类（cat/head/tail/grep）不算外传，放行但记录；
    # 打包/编码/拷贝/网络发送 → 拦截
    if exfil:
        reason = (f"检测到访问敏感凭据文件（{', '.join(touches)}）"
                  f"且伴随打包/编码/外传动作。"
                  f"凭据请勿离开本机；如确需转移请由用户手动操作。")
        json.dump({"decision": "deny", "reason": reason,
                   "message": f"命中特征: {exfil}"}, sys.stdout, ensure_ascii=False)
        return

    json.dump({"message": f"(审计) 访问了凭据相关文件 {touches}，仅查看未外传"},
              sys.stdout)


if __name__ == "__main__":
    sys.exit(main())
