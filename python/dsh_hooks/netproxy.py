#!/usr/bin/env python3
"""netproxy.py — dsh-hooks 域名级网络白名单审查代理(codex-parity M9,Phase E)

对标 Codex network-proxy 的最小安全子集,零第三方依赖(stdlib only):

  AI 进程 ──HTTP CONNECT──▶ 本代理(127.0.0.1:<port> 或 UDS)──域名裁决──▶ 上游
                                │
                                ├─ allow 且无 deny → 盲转发字节流
                                ├─ deny 命中 → 恒拒绝(deny 恒胜,对齐 Codex)
                                └─ 其他 → 默认拒绝(fail-closed)

规则来源 hooks-sandbox.json 的 network 段:
  "allow_remote": ["openrouter.ai:443", "github.com"],   # host 或 host:port;host 条目不限端口
  "deny_remote":  ["*.telemetry.example", "evil.com"]    # deny 恒胜(先收集全部命中再聚合)

安全语义(对齐 Codex connect_policy):
  1. deny 恒胜 allow —— 冲突时不看顺序直接拒
  2. IP 字面量默认拒绝(防 DNS rebinding 绕过域名检查);显式加入白名单才放行
  3. 解析结果必须是公网地址(私网/环回/链路本地一律拒)—— 防 SSRF 打内网
  4. 仅支持 CONNECT(HTTPS 隧道);明文 HTTP 绝对 URI 形式一律 405(fail-closed 方向)
  5. 每条决策写 JSONL 审计(~/.dsh/hooks/netproxy-audit.jsonl)

用法:
  python3 -m dsh_hooks.netproxy --policy ~/.dsh/hooks-sandbox.json \
      --tcp 127.0.0.1:8888 [--uds /run/dsh-netproxy.sock]
"""
import argparse
import fnmatch
import ipaddress
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path

BUFSZ = 65536
AUDIT_DEFAULT = str(Path(os.environ.get("DSH_HOME", os.path.expanduser("~/.dsh")))
                    / "hooks" / "netproxy-audit.jsonl")


# ── 规则模型 ────────────────────────────────────────────────────────────────

class DomainRules:
    """allow/deny 列表;条目 'host' 或 'host:port';支持 '*.example.com' 通配。"""

    def __init__(self, allows: list, denies: list):
        self.allows = [self._parse(x) for x in allows or []]
        self.denies = [self._parse(x) for x in denies or []]

    @staticmethod
    def _parse(entry: str):
        entry = entry.strip().lower()
        host, port = entry, None
        if "]:" in entry:                                   # [::1]:443
            host, _, port = entry[:-1].partition("]:")
            port = int(port)
        elif entry.count(":") == 1 and not entry.startswith("["):
            host, _, p = entry.partition(":")
            port = int(p)
        return (host, port)

    @staticmethod
    def _match_one(host: str, port: int, rule_host: str, rule_port) -> bool:
        if rule_port is not None and port not in (rule_port, None):
            return False
        if rule_host.startswith("*."):
            base = rule_host[2:]
            h = host.lower()
            return h == base or h.endswith("." + base)
        return host.lower() == rule_host

    def decide(self, host: str, port) -> str:
        """返回 'allow' / 'deny-priority' / 'deny-default'(未命中)。"""
        hits_allow = any(self._match_one(host, port, rh, rp) for rh, rp in self.allows)
        hits_deny = any(self._match_one(host, port, rh, rp) for rh, rp in self.denies)
        if hits_deny:
            return "deny-priority"                          # deny 恒胜(Codex 同款)
        if hits_allow:
            return "allow"
        return "deny-default"


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified)


# ── 审计 ────────────────────────────────────────────────────────────────────

_audit_lock = threading.Lock()


def audit(path, **kv):
    rec = {"time": time.strftime("%Y-%m-%dT%H:%M:%S"), **kv}
    line = json.dumps(rec, ensure_ascii=False) + "\n"
    with _audit_lock:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line)


# ── 裁决器 ──────────────────────────────────────────────────────────────────

class Decider:
    def __init__(self, rules: DomainRules, audit_path: str,
                 resolve_check: bool = True):
        self.rules = rules
        self.audit_path = audit_path
        self.resolve_check = resolve_check          # 解析结果须为公网 IP

    def check_connect(self, authority: str, client: str) -> tuple:
        """CONNECT authority('host:port') → (allowed:bool, reason:str)"""
        host, _, port_s = authority.rpartition(":")
        if host.startswith("[") and host.endswith("]"):     # [v6]:port
            host = host[1:-1]
        try:
            port = int(port_s) if port_s else 443
        except ValueError:
            port = 0

        # 1) IP 字面量默认拒绝(防绕域名检查/rebinding)
        literal_ip = False
        try:
            ipaddress.ip_address(host)
            literal_ip = True
        except ValueError:
            pass
        if literal_ip:
            allowed = any(self._match_ip_in_rules(host))
            verdict = ("allow" if allowed else "deny-ip-literal")
        else:
            verdict = self.rules.decide(host, port)

        allowed = verdict == "allow"

        # 2) 解析校验:目标必须解析到公网地址(防 SSRF 打内网/环回)
        if allowed and self.resolve_check and not literal_ip:
            try:
                infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
                ips = {i[4][0] for i in infos}
            except socket.gaierror as e:
                allowed, verdict = False, "dns-fail"
                audit(self.audit_path, decision="deny", reason=verdict,
                      target=f"{host}:{port}", detail=str(e), client=client)
                return False, f"dns 解析失败: {e}"
            bad = [ip for ip in ips if not is_public_ip(ip)]
            if bad:
                allowed, verdict = False, "deny-non-public-resolve"
                audit(self.audit_path, decision="deny", reason=verdict,
                      target=f"{host}:{port}", resolved=sorted(bad), client=client)
                return False, f"目标解析到非公网地址 {sorted(bad)[0]},疑似 SSRF,已拒"

        reason = {"allow": "白名单命中",
                  "deny-priority": "命中 deny 规则(deny 恒胜)",
                  "deny-default": "不在白名单(默认拒绝)",
                  "deny-ip-literal": "IP 字面量默认拒绝"}.get(verdict, verdict)
        audit(self.audit_path, decision="allow" if allowed else "deny",
              reason=verdict, target=f"{host}:{port}", client=client)
        return allowed, reason

    def _match_ip_in_rules(self, ip: str) -> list:
        out = []
        for rh, rp in self.rules.allows + self.rules.denies:
            if rh == ip.lower():
                out.append((rh, rp))
        return out


# ── 隧道转发 ────────────────────────────────────────────────────────────────

def pipe(src, dst, label=""):
    try:
        while True:
            data = src.recv(BUFSZ)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle_client(conn: socket.socket, addr, decider: Decider):
    try:
        conn.settimeout(15)
        first = b""
        while b"\r\n" not in first:
            chunk = conn.recv(BUFSZ)
            if not chunk:
                return
            first += chunk
            if len(first) > BUFSZ:
                break
        head, _, rest = first.partition(b"\r\n")
        parts = head.decode("latin1").split(" ")
        if len(parts) < 2 or parts[0].upper() != "CONNECT":
            conn.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n"
                         b"Connection: close\r\n\r\n")
            audit(decider.audit_path, decision="deny", reason="non-connect",
                  detail=parts[0] if parts else "?", client=str(addr))
            return
        authority = parts[1]
        conn.settimeout(None)
        allowed, why = decider.check_connect(authority, client=str(addr))
        if not allowed:
            body = json.dumps({"error": "dsh-hooks netproxy",
                               "reason": why}, ensure_ascii=False)
            msg = (f"HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n"
                   f"Content-Length: {len(body.encode())}\r\nConnection: close\r\n\r\n{body}")
            conn.sendall(msg.encode())
            return

        host, _, port_s = authority.rpartition(":")
        host = host[1:-1] if host.startswith("[") else host
        upstream = socket.create_connection((host, int(port_s) if port_s else 443),
                                            timeout=10)
        # 注意: rest 是 CONNECT 请求自身的剩余协议头(Host 等),属于代理层,
        # 绝不能转发给上游——上游从客户端的下一个字节(TLS ClientHello)开始
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        t = threading.Thread(target=pipe, args=(conn, upstream, "c>u"), daemon=True)
        t.start()
        pipe(upstream, conn, "u>c")
        t.join(timeout=30)
    except Exception as e:                               # 单连接故障不影响整体服务
        audit(decider.audit_path, decision="error", detail=str(e)[:160],
              client=str(addr))
    finally:
        try:
            conn.close()
        except OSError:
            pass


def serve_tcp(sock_listen: socket.socket, decider: Decider):
    while True:
        try:
            conn, addr = sock_listen.accept()
        except OSError:
            break
        threading.Thread(target=handle_client, args=(conn, addr, decider),
                         daemon=True).start()


def serve_uds(path: str, decider: Decider):
    p = Path(path)
    if p.exists():
        p.unlink()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(path)
    os.chmod(path, 0o666)                                # 跨 UID 场景由文件系统权限管
    s.listen(64)
    serve_tcp(s, decider)


# ── Linux netns 地道(forwarder 模式,Phase E/E2)─────────────────────────────
# bwrap --unshare-net 后沙箱进入无外网的独立 netns;宿主代理的 UDS socket 文件
# 经 bind-mount 递入(Cross-netns 可行:UDS 走文件系统不走网络栈)。本模式:
#   1. 拉起 loopback(netns 内有 user-ns 授权的 CAP_NET_ADMIN)
#   2. 监听 127.0.0.1:<port>,把 TCP 流量转发进 UDS 地道
#   3. exec 真实命令 —— 应用的 HTTP(S)_PROXY 指向 localhost:<port>
SIOCSIFFLAGS = 0x8914


def _bring_lo_up():
    import fcntl
    import struct
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifreq = struct.pack("16sH14s", b"lo", 0x1, b"")     # IFF_UP
        fcntl.ioctl(s.fileno(), SIOCSIFFLAGS, ifreq)
    finally:
        s.close()


def _pipe_tcp_to_uds(client: socket.socket, uds_path: str):
    try:
        remote = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        remote.connect(uds_path)
    except OSError:
        client.close()
        return

    def one_way(a, b):
        try:
            while True:
                d = a.recv(BUFSZ)
                if not d:
                    break
                b.sendall(d)
        except OSError:
            pass
        finally:
            try:
                b.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    t = threading.Thread(target=one_way, args=(client, remote), daemon=True)
    t.start()
    one_way(remote, client)
    t.join(timeout=5)


def run_forwarder(listen_port: int, uds_path: str, cmd):
    """netns 内:拉起 lo + TCP→UDS 转发器后台化 + exec 真实命令"""
    try:
        _bring_lo_up()
    except OSError as e:
        print(f"[netproxy-forwarder] lo up 失败({e});"
              "127.0.0.1 可能不可达", file=sys.stderr)

    fwd = socket.socket()
    fwd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    fwd.bind(("127.0.0.1", listen_port))
    fwd.listen(64)

    def accept_loop():
        while True:
            try:
                c, _ = fwd.accept()
            except OSError:
                return
            threading.Thread(target=_pipe_tcp_to_uds,
                             args=(c, uds_path), daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    sys.stdout.flush()
    os.execvp(cmd[0], cmd)                              # 用真实命令替换自身


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if argv and argv[0] == "forwarder":                  # Linux netns 地道模式
        ap = argparse.ArgumentParser(prog="netproxy forwarder")
        ap.add_argument("--tcp", type=int, required=True, dest="listen_port")
        ap.add_argument("--uds", required=True)
        ap.add_argument("cmd", nargs=argparse.REMAINDER)
        a = ap.parse_args(argv[1:])
        cmd = [c for c in a.cmd if c != "--"]
        run_forwarder(a.listen_port, a.uds, cmd)
        return 0                                          # execvp 不返回

    ap = argparse.ArgumentParser(prog="dsh-hooks-netproxy")
    ap.add_argument("--policy", help="hooks-sandbox.json 路径")
    ap.add_argument("--tcp", help="TCP 监听,如 127.0.0.1:8888")
    ap.add_argument("--uds", help="Unix Domain Socket 监听路径(Linux 地道用)")
    ap.add_argument("--audit", default=os.environ.get("DSH_HOOKS_NETPROXY_AUDIT",
                                                      AUDIT_DEFAULT))
    ap.add_argument("--allow", action="append", default=[],
                    help="额外 allow 条目(覆盖 policy)")
    ap.add_argument("--deny", action="append", default=[],
                    help="额外 deny 条目")
    ap.add_argument("--no-resolve-check", action="store_true",
                    help="关闭『解析须公网』校验(不建议)")
    a = ap.parse_args(argv)

    allows, denies = list(a.allow), list(a.deny)
    if a.policy and Path(a.policy).exists():
        pol = json.loads(Path(a.policy).read_text(encoding="utf-8"))
        net = pol.get("network") or {}
        allows += [str(x) for x in net.get("allow_remote", [])]
        denies += [str(x) for x in net.get("deny_remote", [])]

    if not a.tcp and not a.uds:
        print("需要 --tcp 和/或 --udp(--uds)", file=sys.stderr)
        return 1

    decider = Decider(DomainRules(allows, denies), a.audit,
                      resolve_check=not a.no_resolve_check)
    Path(a.audit).parent.mkdir(parents=True, exist_ok=True)
    threads = []

    if a.tcp:
        host, _, port = a.tcp.rpartition(":")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, int(port)))
        s.listen(128)
        threads.append(threading.Thread(target=serve_tcp, args=(s, decider),
                                        daemon=True))
    if a.uds:
        threads.append(threading.Thread(target=serve_uds, args=(a.uds, decider),
                                        daemon=True))

    for t in threads:
        t.start()
    print(json.dumps({"started": True, "tcp": a.tcp, "uds": a.uds,
                      "allows": len(decider.rules.allows),
                      "denies": len(decider.rules.denies)}, ensure_ascii=False))
    sys.stdout.flush()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
