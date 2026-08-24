#!/usr/bin/env python3
"""execpolicy.py — 命令前缀裁决引擎（codex-parity-design.md M5，Phase D）

对标 Codex execpolicy（Starlark prefix_rule）的核心语义，JSON 数据驱动：

    {
      "rules": [
        {"patterns": [["git", "push"]],
         "decision": "allow",
         "justification": "常规 git 推送",
         "match_tests": ["git push origin main"],
         "not_match_tests": ["git pushx", "echo git push"]}
      ]
    }

四项 Codex 关键语义：
1. 三态决策 allow / prompt / forbidden；多规则命中取最严
   （forbidden > prompt > allow）
2. match/not_match 加载期自测：规则自带正反示例，加载时验证匹配行为，
   自测失败的规则拒绝加载整个策略文件（fail-closed，防写错规则静默放行）
3. BANNED_PREFIX：禁止把 bash/python/rm/sh 等万能前缀持久化放行——
   放行解释器 = 放行一切，amend 请求直接拒绝
4. amendment 热更：审批通过的追加规则写入独立文件，
   mtime 变化即重载（ArcSwap 的 Python 等价物），无需重启进程

CLI：
    python3 -m dsh_hooks.execpolicy check "git push origin main"
    python3 -m dsh_hooks.execpolicy amend --decision allow --command "git push" --justification ...
"""
import json
import logging
import os
import re
import sys
import time
from pathlib import Path

log = logging.getLogger("dsh-hooks")

DECISIONS = ("allow", "prompt", "forbidden")
_SEVERITY = {"allow": 0, "prompt": 1, "forbidden": 2}

# 万能前缀黑名单：对这些 token 的 allow 永久拒绝（Codex BANNED_PREFIX_SUGGESTIONS）
BANNED_PREFIX_TOKENS = {
    "bash", "sh", "zsh", "dash", "python", "python3", "perl", "ruby",
    "node", "osascript", "expect", "sudo", "doas",
    "rm", "mv", "cp", "chmod", "chown", "dd", "mkfs",
}


# ── 规则模型 ────────────────────────────────────────────────────────────────

class PrefixRule:
    __slots__ = ("patterns", "decision", "justification", "name", "_compiled")

    def __init__(self, patterns, decision, justification="", name=""):
        self.patterns = [list(p) for p in patterns]     # [[tok,...],...] 备选列表
        self.decision = decision
        self.justification = justification or ""
        self.name = name
        self._validate()

    def _validate(self):
        if not self.patterns:
            raise ValueError("rule 至少需要一个 pattern")
        if self.decision not in DECISIONS:
            raise ValueError(f"decision 必须是 {DECISIONS}，得到 {self.decision!r}")
        for p in self.patterns:
            if not p or any(not isinstance(t, str) or t == "" for t in p):
                raise ValueError(f"pattern 必须是非空字符串列表: {p!r}")

    def matches(self, command_tokens: list) -> bool:
        """逐前缀比对：pattern 是 command 首 n 个 token 的前缀（任一备选命中即可）"""
        for p in self.patterns:
            n = len(p)
            if len(command_tokens) >= n and command_tokens[:n] == p:
                return True
        return False


TOKENIZE_SPLIT = re.compile(r"\s+")


def tokenize(command: str) -> list:
    """轻量分词（shell 引号感知的最小实现；不做变量展开——裁决在执行前的静态层）"""
    out, cur, quote = [], "", None
    for c in command.strip():
        if quote:
            if c == quote:
                quote = None
            else:
                cur += c
        elif c in "\"'":
            quote = c
        elif c.isspace():
            if cur:
                out.append(cur)
                cur = ""
        else:
            cur += c
    if cur:
        out.append(cur)
    return out


def basename_of(tok: str) -> str:
    """Codex host_executable 语义：/usr/bin/git → git（basename 回退匹配）"""
    return tok.rstrip("/").rsplit("/", 1)[-1]


# ── 加载期自测（fail-closed）───────────────────────────────────────────────

def _selftest_rule(raw: dict, where: str, idx: int) -> PrefixRule:
    rule = PrefixRule(raw.get("patterns") or [],
                      raw.get("decision", ""),
                      raw.get("justification", ""),
                      raw.get("name", ""))
    for t in raw.get("match_tests", []):
        if not rule.matches(tokenize(t)):
            raise ValueError(
                f"{where}: rules[{idx}] ({rule.name or rule.patterns}) "
                f"match_tests 未命中: {t!r} —— 规则与自测不符，拒绝加载")
    for t in raw.get("not_match_tests", []):
        if rule.matches(tokenize(t)):
            raise ValueError(
                f"{where}: rules[{idx}] ({rule.name or rule.patterns}) "
                f"not_match_tests 反而命中: {t!r} —— 规则过宽，拒绝加载")
    # BANNED_PREFIX：allow 一个万能前缀 = 放行一切，加载期即拒绝
    if rule.decision == "allow":
        for p in rule.patterns:
            head = basename_of(p[0]).lower()
            if head in BANNED_PREFIX_TOKENS and len(p) <= 1:
                raise ValueError(
                    f"{where}: rules[{idx}] 试图放行万能前缀 {p[0]!r}"
                    f"（BANNED_PREFIX）；放行解释器等于放行一切，拒绝加载")
    return rule


# ── 策略容器（含 amendment 热更）───────────────────────────────────────────

class ExecPolicy:
    def __init__(self, rules: list, source: str = ""):
        self.rules = rules
        self.source = source
        self._amend_path = Path(os.environ.get(
            "DSH_HOME", os.path.expanduser("~/.dsh"))) / "hooks-execpolicy-amendments.json"
        self._amend_mtime = -1.0
        self._amendments: list = []
        self._reload_amendments(force=True)

    @classmethod
    def load(cls, path: str = None) -> "ExecPolicy":
        candidates = [path] if path else [
            os.environ.get("DSH_HOOKS_EXECPOLICY", ""),
            str(Path(os.environ.get("DSH_HOME", os.path.expanduser("~/.dsh")))
                / "hooks-execpolicy.json"),
        ]
        src = next((c for c in candidates if c and Path(c).exists()), None)
        if src is None:
            return cls([], source="(no policy file)")
        raw = json.loads(Path(src).read_text(encoding="utf-8"))
        rules = [_selftest_rule(r, src, i)
                 for i, r in enumerate(raw.get("rules", []))]
        pol = cls(rules, source=str(src))
        log.info("execpolicy 已加载 %d 条规则（%s），自测通过",
                 len(rules), src)
        return pol

    def _reload_amendments(self, force: bool = False) -> None:
        """amendment 热更：mtime 变化才重新读盘解析"""
        try:
            mt = self._amend_path.stat().st_mtime
        except OSError:
            mt = -1.0
        if not force and mt == self._amend_mtime:
            return
        self._amend_mtime = mt
        try:
            raw = json.loads(self._amend_path.read_text(encoding="utf-8"))
            self._amendments = [
                _selftest_rule(r, str(self._amend_path), i)
                for i, r in enumerate(raw.get("rules", []))
            ]
            log.info("execpolicy amendments 已热更：%d 条", len(self._amendments))
        except (OSError, json.JSONDecodeError, ValueError) as e:
            log.warning("amendments 加载失败(忽略,沿用旧规则): %s", e)

    def decide(self, command: str) -> dict:
        """返回 {"decision","matched","justification"}；无命中 → decision=prompt
        （默认谨慎：没有明确允许的命令交给上层人工/审批层）。"""
        self._reload_amendments()                  # 每次裁决前检查热更
        toks = tokenize(command)
        best, best_rule = -1, None
        for rule in self._amendments + self.rules:  # amendments 优先参与聚合
            if rule.matches(toks):
                sev = _SEVERITY[rule.decision]
                if sev > best:
                    best, best_rule = sev, rule
        if best_rule is None:
            return {"decision": "prompt", "matched": None,
                    "justification": "未命中任何规则，按需审批"}
        return {"decision": best_rule.decision, "matched": best_rule.name
                or str(best_rule.patterns),
                "justification": best_rule.justification}

    # ── amendment 写入（带 BANNED_PREFIX 校验）─────────────────────────────
    def amend(self, patterns: list, decision: str,
              justification: str = "", name: str = "") -> dict:
        if decision != "allow":
            raise ValueError("amendment 仅支持 allow（prompt/forbidden 请改主策略文件）")
        rule_raw = {"patterns": patterns, "decision": decision,
                    "justification": justification, "name": name or "amendment"}
        rule = _selftest_rule(rule_raw, "amendment", 0)   # 同样过自测+BANNED 校验
        try:
            raw = json.loads(self._amend_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raw = {"rules": []}
        raw.setdefault("rules", []).append(rule_raw)
        self._amend_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._amend_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self._amend_path)              # 原子替换（flock 语义的简化等价）
        self._reload_amendments(force=True)
        return {"ok": True, "total_amendments": len(self._amendments)}


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print(__doc__)
        return 1
    cmd, rest = argv[0], argv[1:]
    pol = ExecPolicy.load()
    if cmd == "check":
        command = " ".join(rest)
        print(json.dumps(pol.decide(command), ensure_ascii=False, indent=2))
        d = pol.decide(command)["decision"]
        return 0 if d == "allow" else (2 if d == "forbidden" else 3)
    if cmd == "amend":
        opts = dict(zip(rest[::2], rest[1::2]))
        r = pol.amend(patterns=[tokenize(opts["--command"])],
                      decision=opts["--decision"],
                      justification=opts.get("--justification", ""),
                      name=opts.get("--name", ""))
        print(json.dumps(r, ensure_ascii=False))
        return 0
    print(f"未知子命令 {cmd}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
