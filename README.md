# 📦 DSH 安全套件(@zhbcher/dsh-security-suite)

**一条命令安装的 DeepSeek Harness 一体化安全插件**:钩子总线 + 七层防线 + OS 沙箱策略 + 域名白名单代理 + Codex 强制层复用。

```
📦 DSH 安全套件(本仓库)
├── 🔌 plugin/            ← 插件入口:把门卫接到 DSH 官方打卡机
│                           🆕 首次激活自举:定位 Python 核心/写默认配置/
│                              生成出口哨兵/trust 引导(失败降级仅拦截层)
├── 🧠 python/dsh_hooks/  ← 大脑:规则与判断
│   ├── 钩子总线+五守卫+渠道无关出口哨兵+autodiscover 自学习
│   ├── trust.py          防篡改门(配置指纹,modified 必须重新确认)
│   ├── execpolicy.py     命令前缀裁决引擎(deny恒胜/match自测/BANNED_PREFIX/热更)
│   ├── netproxy.py       网络域名白名单登记处(CONNECT/deny恒胜/SSRF防护)
│   └── sandbox/          策略模型+macOS Seatbelt 动态 sbpl+bwrap+Codex 翻译官
├── 🏠 bin/dsh-suite      ← 笼子在外面(架构必然):统一 CLI 与 headless 包装命令
├── ⚙️ resources/         ← 默认 hooks.json / 沙箱策略 / 示例
├── 🦀 .github/workflows/ ← Codex 复用层:codel-linux-sandbox 三平台构建流水线
└── 📖 docs/              ← Windows 网络代理指南等
```

## 安装

```bash
dsh plugin --profile <你的profile> add /path/to/dsh-security-suite
# 首次激活自动自举:写默认 hooks.json(不覆盖已有)/生成出口哨兵/trust 引导
```

前置:`python3` 可用(Python 核心随包分发,零 pip 依赖)。

## 统一命令行

```bash
bin/dsh-suite status        # 总览:总线钩子/信任状态/哨兵
bin/dsh-suite trust         # 固化当前配置指纹(防篡改门)
dsh-suite run-headless "任务"   # 以沙箱+网络审查运行一次 headless 任务
```

## 架构铁律

1. **纯插件零侵入**:不修改 DSH 内核,升级零影响;
2. **笼子在外面**:包裹 DSH 进程树的沙箱启动器永远在宿主外侧——插件内无法包裹自己的宿主,这是架构必然;headless 场景由网关 `DSH_HOOKS_SANDBOX=1` 或 `run-headless` 包装命令接入。

## 与 OpenAI Codex 的关系

对标 Codex(Apache-2.0)安全体系并复用其官方组件:
- 判定语义对齐:deny 恒胜 / IP 字面量防护 / SSRF 校验 / fail-closed / match 自测 / BANNED_PREFIX;
- `codex-linux-sandbox` 二进制(Linux seccomp 强制层)经 Actions 流水线直接复用;
- 差异与独有能力见 [research 对比报告](https://github.com/zhbcher/dsh-hooks) 或仓库内文档。

## 配套组件

- [dsh-memory-pipeline](https://github.com/zhbcher):记忆两阶段流水线(独立工具)

## License

MIT(自有代码)· 内嵌 Codex 组件遵循 Apache-2.0
