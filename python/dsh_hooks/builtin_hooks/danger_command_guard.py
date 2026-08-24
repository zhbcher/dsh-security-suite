#!/usr/bin/env python3
"""内置钩子：危险命令守卫（挂 PreToolUse，matcher 建议 Bash|Shell|Python）

对 Bash 类工具的 command 做内容级安检：
  - 禁止类（forbidden）：sudo/su 提权、mkfs/dd 写裸设备、关机重启、
    rm -rf 根或家目录、launchctl unload
  - 谨慎类（prompt → 以 deny 呈现给上层人工确认）：curl|sh 管道执行、
    git push --force、chmod -R 777
命中即拦截并给出中文理由与替代建议；未命中放行。

这是 dsh-execpolicy 完整规则引擎的精简单文件版，开箱即用。
"""
import json
import re
import sys

# (名称, 正则, 理由/替代建议)
FORBIDDEN = [
    ("提权", r"^\s*(sudo|doas)\b",
     "禁止提权操作；如需安装系统软件请让用户手动执行"),
    ("裸设备写入", r"\bdd\b[^|]*\bof=/dev/(disk|sd|nvme)",
     "禁止向裸设备写入"),
    ("格式化", r"\bmkfs(\.\w+)?\b", "禁止格式化文件系统"),
    ("关机重启", r"^\s*(shutdown|reboot|halt)\b", "禁止关闭/重启系统"),
    ("卸载系统服务", r"\blaunchctl\s+unload\b",
     "禁止卸载系统服务；可用 kickstart -k 重启单个服务"),
]

CAUTION = [
    ("管道执行远程脚本", r"(curl|wget)\s+\S+\s*\|\s*(ba|z|da)?sh\b",
     "下载脚本直接执行有供应链风险；请先下载审查内容再运行"),
    ("强删根/家目录", r"rm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+)*-[a-zA-Z]*[rf][a-zA-Z]*"
     r"\s+(~|\$HOME|/)(\s|$|/)",
     "递归强删根目录/家目录极其危险；请明确具体子路径"),
    ("强推远端", r"git\s+push\s+.*(--force\b|--force-with-lease=)",
     "强制推送会覆盖远端历史；确认分支无他人协作？"),
    ("全局开放权限", r"chmod\s+-R\s+777\s+/", "不建议对根路径开放全部权限"),
]


def check(command: str) -> list:
    """返回命中的 [(级别, 名称, 理由)]。按 && ; || 切段逐段检查。"""
    hits = []
    segments = re.split(r"&&|;|\|\|", command)
    for seg in segments:
        seg = seg.strip()
        if not seg:
            continue
        for level, table in (("forbidden", FORBIDDEN), ("caution", CAUTION)):
            for name, pattern, reason in table:
                if re.search(pattern, seg):
                    hits.append((level, name, reason))
    return hits


def main():
    payload = json.load(sys.stdin)
    data = payload.get("data") or {}
    tool = str(data.get("tool_name", ""))
    if tool.lower() not in ("bash", "shell", "python", "zsh"):
        json.dump({}, sys.stdout)          # 非命令类工具直接放行
        return
    command = str((data.get("tool_input") or {}).get("command", ""))
    if not command:
        json.dump({}, sys.stdout)
        return

    hits = check(command)
    if not hits:
        json.dump({}, sys.stdout)
        return

    forbidden = [h for h in hits if h[0] == "forbidden"]
    reasons = [f"[{name}] {reason}" for _, name, reason in hits]
    decision = "deny" if forbidden else "rewrite"
    # caution 类以 deny 返回但理由注明"需人工确认"，由上层决定是否放行
    out = {"decision": "deny",
           "reason": "命令安检未通过：" + "；".join(reasons)}
    if not forbidden:                      # 仅谨慎类：附上原命令供人工复核
        out["message"] = f"谨慎命令（建议人工确认）：{command[:200]}"
    json.dump(out, sys.stdout, ensure_ascii=False)


if __name__ == "__main__":
    sys.exit(main())
