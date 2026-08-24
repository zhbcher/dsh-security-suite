#!/usr/bin/env python3
"""netproxy 单元测试 —— 纯裁决逻辑 + 真实 TCP 隧道端到端。零第三方依赖。
运行: python3 -m unittest tests.test_netproxy -v
"""
import ipaddress
import json
import socket
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dsh_hooks.netproxy import DomainRules, Decider, is_public_ip, serve_tcp  # noqa: E402


class TestDomainRules(unittest.TestCase):
    def test_exact_and_wildcard(self):
        r = DomainRules(["openrouter.ai:443", "github.com", "*.example.org"],
                        ["*.evil.tk"])
        self.assertEqual(r.decide("openrouter.ai", 443), "allow")
        self.assertEqual(r.decide("openrouter.ai", 80), "deny-default")   # 条目限 443
        self.assertEqual(r.decide("github.com", 443), "allow")            # 不限端口
        self.assertEqual(r.decide("api.github.com", 443), "deny-default") # 通配不跨级
        self.assertEqual(r.decide("a.example.org", 443), "allow")
        self.assertEqual(r.decide("example.org", 443), "allow")           # *.base 含自身
        self.assertEqual(r.decide("sub.evil.tk", 1), "deny-priority")

    def test_deny_wins_over_allow(self):
        r = DomainRules(["*.corp.com"], ["secret.corp.com"])
        self.assertEqual(r.decide("ok.corp.com", 443), "allow")
        self.assertEqual(r.decide("secret.corp.com", 443), "deny-priority")  # deny 恒胜


class TestIpGuards(unittest.TestCase):
    def test_is_public_ip(self):
        self.assertTrue(is_public_ip("1.2.3.4"))
        self.assertFalse(is_public_ip("127.0.0.1"))
        self.assertFalse(is_public_ip("192.168.1.1"))
        self.assertFalse(is_public_ip("10.0.0.5"))
        self.assertFalse(is_public_ip("169.254.1.1"))
        self.assertFalse(is_public_ip("::1"))

    def test_ip_literal_denied_unless_allowlisted(self):
        r = DomainRules([], [])
        d = Decider(r, "/dev/null")
        ok, why = d.check_connect("93.184.216.34:443", client="t")
        self.assertFalse(ok)
        r2 = DomainRules(["93.184.216.34"], [])
        d2 = Decider(r2, "/dev/null")
        ok2, _ = d2.check_connect("93.184.216.34:443", client="t")
        self.assertTrue(ok2)


class TestEndToEnd(unittest.TestCase):
    """起真代理+真上游,走完整 CONNECT 隧道验证白名单双向生效。"""

    @classmethod
    def setUpClass(cls):
        # 假上游:本机回环 HTTP 服务(返回固定行)——用非公网地址会被 SSRF 防护拒,
        # 所以端到端用 --no-resolve-check 且显式 allow 127.0.0.1
        cls.upstream = socket.socket()
        cls.upstream.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        cls.upstream.bind(("127.0.0.1", 0))
        cls.upstream.listen(8)
        cls.up_port = cls.upstream.getsockname()[1]
        threading.Thread(target=cls._fake_upstream, args=(cls.upstream,),
                         daemon=True).start()

        cls.proxy = socket.socket()
        cls.proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        cls.proxy.bind(("127.0.0.1", 0))
        cls.proxy.listen(16)
        cls.proxy_port = cls.proxy.getsockname()[1]
        rules = DomainRules([f"127.0.0.1:{cls.up_port}"], ["blocked.test"])
        dec = Decider(rules, "/dev/null", resolve_check=False)
        threading.Thread(target=serve_tcp, args=(cls.proxy, dec),
                         daemon=True).start()

    @classmethod
    def _fake_upstream(cls, sock):
        while True:
            try:
                c, _ = sock.accept()
            except OSError:
                return

            def serve(c=c):
                try:
                    c.recv(BUFSZ := 65536)
                    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
                    c.close()
                except OSError:
                    pass
            threading.Thread(target=serve, daemon=True).start()

    def _connect(self, authority):
        c = socket.create_connection(("127.0.0.1", self.proxy_port), timeout=5)
        c.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = c.recv(4096)
            if not chunk:
                break
            resp += chunk
        return c, resp

    def test_allowlist_tunnel_carries_traffic(self):
        c, resp = self._connect(f"127.0.0.1:{self.up_port}")
        self.assertIn(b"200", resp.split(b"\r\n")[0], resp[:120])
        c.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        data = c.recv(65536)
        self.assertIn(b"hi", data)
        c.close()

    def test_deny_rule_rejects_with_403(self):
        c, resp = self._connect("blocked.test:443")
        self.assertIn(b"403", resp.split(b"\r\n")[0])
        c.close()

    def test_default_deny(self):
        c, resp = self._connect("unknown.test:443")
        self.assertIn(b"403", resp.split(b"\r\n")[0])
        c.close()


if __name__ == "__main__":
    unittest.main()
