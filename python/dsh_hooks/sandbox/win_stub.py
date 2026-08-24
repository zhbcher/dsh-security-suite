#!/usr/bin/env python3
"""win_stub.py — Windows 平台 fail-closed 桩

依据 codex-parity-design.md §1.2 与残余风险声明 #1：
Windows RestrictedToken 的 WRITE_RESTRICTED 读不受限 → unelevated 后端
做不了 deny-read。Codex 的选择是 fail-closed 直接拒绝执行；
Elevated 后端（专用受限账户 + deny ACL + 私桌面 + WFP）列为后续工作。

本桩在 wrap_argv 入口即拒绝——绝不在无法表达策略的平台上裸跑。
"""


class WindowsSandboxUnsupported(RuntimeError):
    pass


def wrap_argv(policy, argv):
    has_secret_guard = bool(getattr(policy, "deny_read", []))
    net_restricted = getattr(policy, "network", None) is not None and \
        getattr(policy.network, "mode", "") == "restricted"
    if has_secret_guard or net_restricted:
        raise WindowsSandboxUnsupported(
            "Windows unelevated 无法强制 deny_read/restricted 网络"
            "（WRITE_RESTRICTED 只限写不限读）。按 fail-closed 拒绝执行；"
            "Elevated 专用账户后端见方案 Phase B 后续。")
    # 无秘密保护诉求时仍拒绝——保持行为可预期，等 Elevated 后端落地
    raise WindowsSandboxUnsupported(
        "Windows 后端尚未实现（规划：Elevated 专用账户 + deny ACL + WFP）。")
