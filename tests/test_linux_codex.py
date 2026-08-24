#!/usr/bin/env python3
"""linux_codex 包裹器测试 —— 不依赖真实二进制,验证 argv/profile 组装。
运行: python3 -m unittest tests.test_linux_codex -v
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dsh_hooks.sandbox.codex_profile import to_permission_profile          # noqa: E402
from dsh_hooks.sandbox.policy import load_policy                           # noqa: E402


class TestCodexProfileConversion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = load_policy(str(Path(__file__).parent / "e1-policy.json")
                                 if (Path(__file__).parent / "e1-policy.json").exists()
                                 else "/tmp/e1-policy.json")

    def test_managed_shape(self):
        p = to_permission_profile(self.policy)
        self.assertEqual(p["type"], "managed")
        self.assertEqual(p["file_system"]["type"], "restricted")
        self.assertIn(p["network"], ("restricted", "enabled"))

    def test_writable_roots_become_write_entries(self):
        p = to_permission_profile(self.policy)
        writes = [e for e in p["file_system"]["entries"] if e["access"] == "write"]
        paths = {e["path"]["path"] for e in writes}
        for root in self.policy.writable_roots:
            self.assertIn(root.path, paths)

    def test_deny_read_becomes_deny_globs(self):
        p = to_permission_profile(self.policy)
        denies = [e for e in p["file_system"]["entries"] if e["access"] == "deny"]
        if self.policy.deny_read:                       # e1 策略无 deny_read 时跳过
            self.assertTrue(len(denies) >= len(self.policy.deny_read))
            for e in denies:                            # Codex 限制: glob 仅支持 deny
                self.assertEqual(e["path"]["type"], "glob_pattern")

    def test_network_mapping(self):
        pol = load_policy.__wrapped__ if hasattr(load_policy, "__wrapped__") else None
        # full → enabled
        import dsh_hooks.sandbox.policy as pm
        raw = {"mode": "workspace-write",
               "writable_roots": ["/tmp"],
               "network": {"mode": "full"}}
        Path_ = pm
        pol_full = pm.load_policy.__globals__["SandboxPolicy"](
            mode="workspace-write",
            writable_roots=[pm._parse_root("/tmp", "t")],
            network=pm.NetworkPolicy(mode="full"))
        self.assertEqual(to_permission_profile(pol_full)["network"], "enabled")
        pol_dis = pm.SandboxPolicy(
            mode="workspace-write",
            writable_roots=[pm._parse_root("/tmp", "t")],
            network=pm.NetworkPolicy(mode="disabled"))
        self.assertEqual(to_permission_profile(pol_dis)["network"], "restricted")


class TestWrapArgv(unittest.TestCase):
    def test_argv_assembly_with_fake_bin(self):
        import tempfile
        fake = tempfile.NamedTemporaryFile(delete=False, suffix=".sandbox")
        fake.close()
        import os
        os.chmod(fake.name, 0o755)
        from dsh_hooks.sandbox.linux_codex import wrap_argv
        pol = load_policy("/tmp/e1-policy.json") if Path("/tmp/e1-policy.json").exists() \
            else None
        if pol is None or pol.network.mode == "restricted":
            self.skipTest("需要非 restricted 示例策略")
        argv = wrap_argv(pol, ["echo", "hi"], sandbox_bin=fake.name)
        self.assertEqual(argv[0], fake.name)
        i = argv.index("--permission-profile")
        profile = json.loads(argv[i + 1])
        self.assertEqual(profile["type"], "managed")
        j = argv.index("--")
        self.assertEqual(argv[j + 1:], ["echo", "hi"])
        fake.close()


if __name__ == "__main__":
    unittest.main()
