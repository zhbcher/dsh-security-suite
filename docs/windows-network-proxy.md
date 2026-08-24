# DSH-Hooks 网络白名单代理 —— Windows 接入指南(Phase E/E3)

## 支持等级(诚实声明)

| 层 | 能力 | Windows 状态 |
|---|---|---|
| L1 | netproxy 审查代理本体(Python stdlib,跨平台) | ✅ 可用 |
| L2 | HTTP(S)_PROXY 环境变量注入(应用自愿走代理) | ✅ 可用 |
| L3 | 出站强制(内核级:不走代理就出不了网) | ⚠️ 尽力而为:netsh 防火墙模板 |
| L4 | Codex 同款 WFP/SID 归因(per-SID 连接审计) | ❌ 需 Windows 真机开发,暂缺 |

与 macOS/Linux 不同,Windows 没有"给单个进程树套网络命名空间"的通用机制;
Codex 用 RestrictedToken+专用账户+WFP 实现。L4 需要在真机上开发 C#/Rust
过滤驱动或 Callout API,当前以 L1-L3 组合提供"尽力而为"的域名白名单。

## L1+L2:启动代理并注入环境(PowerShell)

```powershell
# 1. 启动审查代理(规则读 hooks-sandbox.json 的 allow_remote/deny_remote)
Start-Process python -ArgumentList '-m','dsh_hooks.netproxy',`
  '--tcp','127.0.0.1:18777','--policy',"$env:USERPROFILE\.dsh\hooks-sandbox.json"`
  -WindowStyle Hidden

# 2. 会话级环境变量(之后从该终端启动的 dsh/agent 都会走代理)
$env:HTTP_PROXY  = "http://127.0.0.1:18777"
$env:HTTPS_PROXY = "http://127.0.0.1:18777"
$env:ALL_PROXY   = $env:HTTP_PROXY
$env:NO_PROXY    = "localhost,127.0.0.1"
```

## L3:防火墙强制模板(管理员 PowerShell)

思路:**默认拒绝所有用户程序出站**,只放行「到本机代理端口」的连接和
「代理进程自身的出站」。执行前务必确认理解每条规则(锁死自己出网需手动删规则)。

```powershell
# 0) 先放行代理进程自身的全部出站(按实际 python 路径调整)
pythonPath = (Get-Command python).Source
New-NetFirewallRule -DisplayName "dsh-netproxy outbound" -Direction Outbound `
  -Program $pythonPath -Action Allow

# 1) 默认阻止所有程序出站 TCP 443/80(测试期建议先只对特定 exe 启用)
New-NetFirewallRule -DisplayName "dsh-block-out-443" -Direction Outbound `
  -Protocol TCP -RemotePort 443 -Action Block

# 2) 允许受控程序(AI 的 node/python)连本机代理端口
New-NetFirewallRule -DisplayName "dsh-allow-to-proxy" -Direction Outbound `
  -Protocol TCP -RemotePort 18777 -Program $pythonPath -Action Allow
```

⚠️ 规则 1 是全局的,会影响你自己的浏览器等所有程序。更精细的按程序白名单/
WFP 归因需要真机迭代;执行前建议 `-WhatIf` 演练,并保留删除命令:
`Get-NetFirewallRule -DisplayName "dsh-*" | Remove-NetFirewallRule`

## 与 dsh_hooks.sandbox 的关系

Windows 上 `wrap_argv()` 仍保持 fail-closed(OS 边界无法保证 deny_read);
L1/L2 的代理能力是独立可用的,不经过沙箱包裹路径。
