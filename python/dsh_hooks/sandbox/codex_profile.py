#!/usr/bin/env python3
"""codex_profile.py — hooks-sandbox.json → Codex PermissionProfile 转换器(Phase E/B3)

把我们的策略翻译成 codex-linux-sandbox `--permission-profile <JSON>` 契约
(源码依据 third_party/codex/codex-rs/protocol/src/models.rs L414 起):

    PermissionProfile::Managed {
      file_system: ManagedFileSystemPermissions::Restricted{entries},
      network: NetworkSandboxPolicy(Restricted|Enabled),
    }
  - serde tag="type", snake_case;
  - entries: {path:{type:"path",path},access:read|write|deny}
             |{path:{type:"glob_pattern",pattern},access:"deny"}  ← glob 仅支持 deny
  - 未提及的路径默认只读;同路径更窄条目胜出(narrower wins)

映射规则:
  writable_roots            → entries[{path,access:"write"}]
    .exclude_literals/subtrees → 同路径 {access:"read"} 覆盖(窄者胜)
  deny_read(glob)           → entries[{glob_pattern,access:"deny"}](天然契合)
  network.full              → "enabled"
  network.disabled/restricted → "restricted"(restricted 的出网走我们的代理地道)
"""
import json
import json
from pathlib import Path

from .policy import SandboxPolicy


def _path_entry(path: str, access: str) -> dict:
    return {"path": {"type": "path", "path": path}, "access": access}


def _glob_entry(pattern: str) -> dict:
    # Codex 限制: glob 条目仅支持 Deny —— 与 deny_read 的用途天然一致
    return {"path": {"type": "glob_pattern", "pattern": pattern}, "access": "deny"}


def to_permission_profile(policy: SandboxPolicy) -> dict:
    entries = []
    for root in policy.writable_roots:
        entries.append(_path_entry(root.path, "write"))
        for lit in root.exclude_literals:          # 可写根内的只读子路径(窄者胜)
            entries.append(_path_entry(lit, "read"))
        for sub in root.exclude_subtrees:
            entries.append(_path_entry(sub, "read"))

    for g in policy.deny_read:
        if "*" in g or "?" in g:
            entries.append(_glob_entry(g))         # glob → deny(Codex 仅支持 deny)
        else:
            entries.append(_path_entry(g, "deny"))  # 字面量秘密路径同样 deny

    if policy.network.mode == "full":
        network = "enabled"
    else:                                          # disabled / restricted
        network = "restricted"

    return {
        "type": "managed",
        "file_system": {"type": "restricted", "entries": entries},
        "network": network,
    }


def write_profile_json(policy: SandboxPolicy, out_path: str) -> str:
    data = to_permission_profile(policy)
    Path(out_path).write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return out_path


if __name__ == "__main__":
    import sys
    from .policy import load_policy

    pol = load_policy(sys.argv[1] if len(sys.argv) > 1 else None)
    print(json.dumps(to_permission_profile(pol), ensure_ascii=False, indent=2))
