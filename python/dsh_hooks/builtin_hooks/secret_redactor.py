#!/usr/bin/env python3
"""内置钩子：泄密哨兵（可挂 UserPromptSubmit / PreToolUse / PostToolUse）

递归遍历载荷中的所有字符串，把疑似秘密替换为占位符，
再以 {"decision":"rewrite","data":...} 返回改写后的载荷。

覆盖形态：sk- 开头密钥 / AWS AKIA / GitHub token / Slack token /
PEM 私钥块 / password=… 键值对 / Bearer 头 / 中国大陆手机号。
"""
import json
import re
import sys

RULES = [
    (re.compile(r"sk-[A-Za-z0-9_\-]{16,}"), "<REDACTED_KEY>"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "<REDACTED_AWS_KEY>"),
    (re.compile(r"(ghp_|gho_|github_pat_)[A-Za-z0-9_]{20,}"), "<REDACTED_GH_TOKEN>"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"), "<REDACTED_SLACK_TOKEN>"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
     "<REDACTED_PRIVATE_KEY>"),
    (re.compile(r"""(?i)\b(password|passwd|pwd|secret|token|api[-_]?key|apikey)\b\s*[:=]\s*["']?[^\s"',;]{4,}"""),
     r"\1=<REDACTED>"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{16,}"), "Bearer <REDACTED>"),
    (re.compile(r"\b(1[3-9]\d)\d{4}(\d{4})\b"), r"\1****\2"),
]


def redact(obj):
    """递归处理 dict/list/str，返回净化后的同构对象与命中次数。"""
    hits = 0
    if isinstance(obj, str):
        out = obj
        for pattern, repl in RULES:
            out, n = pattern.subn(repl, out)
            hits += n
        return out, hits
    if isinstance(obj, list):
        items = []
        for item in obj:
            new, h = redact(item)
            items.append(new)
            hits += h
        return items, hits
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            new, h = redact(v)
            out[k] = new
            hits += h
        return out, hits
    return obj, hits


def main():
    payload = json.load(sys.stdin)
    data = payload.get("data") or {}
    cleaned, hits = redact(data)
    if hits:
        json.dump({"decision": "rewrite", "data": cleaned,
                   "message": f"已脱敏 {hits} 处疑似敏感信息"}, sys.stdout,
                  ensure_ascii=False)
    else:
        json.dump({}, sys.stdout)


if __name__ == "__main__":
    sys.exit(main())
