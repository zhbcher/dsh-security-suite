#!/usr/bin/env python3
"""dsh web 重启编排 v2 —— 修复「agent 无法自动重启」的结构性问题。

与 v1(/tmp/dsh-web-restart-result.txt,失败对照)的三点差异:
  1. fork + os.setsid():彻底脱离 DSH 宿主进程树,宿主死亡不再连带清杀
  2. 旧进程死后由 launchd 按 com.dsh.web.plist 接管(RunAtLoad+KeepAlive)
  3. 全程逐步落盘 /tmp/dsh-web-restart-v2.log
"""
import os
import subprocess
import sys
import time
import urllib.request

LOG = "/tmp/dsh-web-restart-v2.log"
UID_N = os.getuid()
LABEL = "com.dsh.web"
PLIST = os.path.expanduser("~/Library/LaunchAgents/com.dsh.web.plist")


def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    with open(LOG, "a") as f:
        f.write(line + "\n")


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def main():
    log("=== v2 编排启动(已 setsid 脱离宿主进程树)===")
    r = sh(["pgrep", "-fl", "_npx.*bin/dsh web"])
    log(f"启动前 web 进程: {r.stdout.strip() or '(无)'}")

    log(f"阶段0: sleep 18s 等待 agent 回合落盘...")
    time.sleep(18)

    log("阶段1: 终止手动 web 进程(此动作将同时终止发起本次编排的 agent)")
    r = sh(["lsof", "-tiTCP:3080", "-sTCP:LISTEN"])
    pids = [x.strip() for x in r.stdout.split() if x.strip()]
    log(f"3080 占用者: {pids or '(无)'}")
    for p in pids:
        subprocess.run(["kill", p])
        log(f"  kill {p}")
    time.sleep(4)
    r = sh(["lsof", "-tiTCP:3080", "-sTCP:LISTEN"])
    log(f"4s 后 3080 占用者: {r.stdout.strip() or '(已释放)'}")

    log("阶段2: launchd 接管(bootout 幂等清理 + bootstrap 按 plist 拉起)")
    b_out = sh(["launchctl", "bootout", f"gui/{UID_N}/{LABEL}"])
    log(f"bootout rc={b_out.returncode} {(b_out.stderr or '').strip()[:120]}")
    b = sh(["launchctl", "bootstrap", f"gui/{UID_N}", PLIST])
    log(f"bootstrap rc={b.returncode} {(b.stderr or '').strip()[:200]}")

    log("阶段3: 轮询健康检查(最长 90s)")
    ok = False
    waited = 0
    for i in range(45):
        time.sleep(2)
        waited = (i + 1) * 2
        try:
            with urllib.request.urlopen("http://127.0.0.1:3080", timeout=2) as resp:
                if resp.status == 200:
                    ok = True
                    break
        except Exception:
            pass
    log(f"健康检查: {'HTTP 200 ✓' if ok else 'FAIL ✗'}(等待 {waited}s)")

    r = sh(["bash", "-c", "launchctl list | grep com.dsh.web"])
    log(f"launchd 注册状态: {r.stdout.strip() or '(未注册!)'}")
    r = sh(["pgrep", "-fl", "_npx.*bin/dsh web"])
    log(f"新 web 进程: {r.stdout.strip() or '(未找到)'}")
    log(f"=== 结果: {'SUCCESS' if ok else 'FAIL'} ===")


if __name__ == "__main__":
    # 关键一步:fork 子进程并 setsid,父进程立即退出,
    # 使编排进程脱离 DSH 的进程组与会话(上次 v1 失败的直接对症修复)
    child = os.fork()
    if child > 0:
        print(f"编排已在后台启动(守护 PID={child}),日志: {LOG}")
        sys.exit(0)
    os.setsid()
    main()
