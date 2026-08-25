/**
 * @zhbcher/dsh-security-suite — DSH 一体化安全套件插件
 *
 * 架构角色(四件套中的 🔌 插件层):
 *   tools/pre-execute  → dsh_hooks 总线 PreToolUse   → deny 直接拦截工具调用
 *   tools/post-execute → dsh_hooks 总线 PostToolUse  → observe-only 审计流水
 *
 * 🆕 首次激活自举(bootstrap,幂等且保守):
 *   1. 校验包内 Python 核心(python/dsh_hooks)可用性 —— 零安装,随包分发;
 *   2. ~/.dsh/hooks.json 不存在时写入默认五事件配置(已存在绝不覆盖);
 *   3. 生成渠道出口哨兵(install-sentinels,重复执行无害);
 *   4. trust 状态检查(untracked 仅提示;modified 阻断总线由 CLI 层负责)。
 *   任何一步失败都降级为「仅拦截层生效」并告警 —— 安全增强不绑架可用性。
 *
 * 沙箱启动器(笼子)按架构必然留在宿主外侧:
 *   使用 bin/dsh-suite run-headless 包装命令或 lark_bridge 的
 *   DSH_HOOKS_SANDBOX=1 开关,见 README「沙箱启动器」一节。
 */
import { spawn } from 'node:child_process'
import { existsSync, copyFileSync, mkdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

export const name = 'dsh-security-suite'
export const inject = []

const PKG_ROOT = fileURLToPath(new URL('../..', import.meta.url))  // 包根(从 plugin/lib/ 上跳两级)
const PY_CORE = join(PKG_ROOT, 'python')                          // PYTHONPATH 指向处

// ── 原 bridge 的代理调用逻辑(不变) ──────────────────────────────────────────

const DEFAULTS = {
  pythonBin: process.env.DSH_HOOKS_PYTHON || 'python3',
  hooksPkgRoot: PY_CORE,                    // 🆕 自举后默认指向包内 Python 核心
  preTimeoutMs: 8000,
  postTimeoutMs: 4000,
  failOpen: true,
  breakerThreshold: 3,
  breakerResetMs: 60_000,
}

function resolveLauncher(cfg) {
  const envCli = process.env.DSH_HOOKS_CLI
  if (envCli) return { argv: [envCli], env: {} }
  const root = cfg.hooksPkgRoot || ''
  if (root && existsSync(join(root, 'dsh_hooks', 'cli.py'))) {
    return {
      argv: [cfg.pythonBin, '-m', 'dsh_hooks.cli'],
      env: { PYTHONPATH: process.env.PYTHONPATH ? `${root}:${process.env.PYTHONPATH}` : root },
    }
  }
  return null
}

function emitEvent(launcher, event, envelope, timeoutMs) {
  return new Promise((resolve, reject) => {
    const child = spawn(launcher.argv[0],
      [...launcher.argv.slice(1), 'emit', event],
      { env: { ...process.env, ...launcher.env }, stdio: ['pipe', 'pipe', 'pipe'] })
    let out = '', err = '', done = false
    const timer = setTimeout(() => {
      if (done) return
      done = true
      child.kill('SIGKILL')
      reject(new Error(`总线 ${event} 超时(${timeoutMs}ms)`))
    }, timeoutMs)
    child.stdout.on('data', (d) => { out += d })
    child.stderr.on('data', (d) => { err += d })
    child.on('error', (e) => {
      if (done) return
      done = true; clearTimeout(timer)
      reject(new Error(`无法启动 dsh-hooks CLI: ${e.message}`))
    })
    child.on('close', (code) => {
      if (done) return
      done = true; clearTimeout(timer)
      try {
        resolve({ ...JSON.parse(out), exitCode: code ?? -1 })
      } catch {
        reject(new Error(`总线输出非法: ${out.slice(0, 120)} ${err.slice(0, 120)}`))
      }
    })
    child.stdin.on('error', () => {})
    child.stdin.write(JSON.stringify(envelope))
    child.stdin.end()
  })
}

function buildEnvelope(exec, extraData) {
  return {
    data: {
      tool_name: String(exec?.name ?? ''),
      tool_input: exec?.arguments ?? {},
      ...(extraData || {}),
    },
    session: {
      id: exec?.agent?.session?.id,
      cwd: exec?.agent?.session?.header?.cwd,
    },
  }
}

// ── 首次激活自举 ────────────────────────────────────────────────────────────

function dshHome() {
  return process.env.DSH_HOME || join(homedir(), '.dsh')
}

function runPythonCore(args, timeoutMs = 30_000) {
  return new Promise((resolve) => {
    const child = spawn(DEFAULTS.pythonBin,
      ['-m', 'dsh_hooks.cli', ...args],
      { cwd: PKG_ROOT, env: { ...process.env, PYTHONPATH: PY_CORE },
        stdio: ['ignore', 'pipe', 'pipe'] })
    let out = '', err = ''
    const timer = setTimeout(() => { child.kill(); resolve({ code: -1, out, err }) }, timeoutMs)
    child.stdout.on('data', (d) => { out += d })
    child.stderr.on('data', (d) => { err += d })
    child.on('close', (code) => { clearTimeout(timer); resolve({ code: code ?? -1, out, err }) })
    child.on('error', (e) => { clearTimeout(timer); resolve({ code: -1, out, err: String(e) }) })
  })
}

async function bootstrap() {
  const steps = []
  // 1. Python 核心自检(随包分发,理论必过;防包损坏)
  steps.push(['python-core', existsSync(join(PY_CORE, 'dsh_hooks', 'cli.py'))
    ? 'ok' : 'MISSING python/dsh_hooks/cli.py'])

  // 2. 默认 hooks.json(不存在才写,绝不覆盖用户配置)
  const hooksJson = join(dshHome(), 'hooks.json')
  if (!existsSync(hooksJson)) {
    const tpl = join(PKG_ROOT, 'resources', 'hooks.default.json')
    if (existsSync(tpl)) {
      mkdirSync(dshHome(), { recursive: true })
      copyFileSync(tpl, hooksJson)
      steps.push(['hooks.json', `已写入默认配置 → ${hooksJson}`])
    } else {
      steps.push(['hooks.json', '模板缺失,跳过'])
    }
  } else {
    steps.push(['hooks.json', '已存在,保留用户配置'])
  }

  // 3. 出口哨兵(幂等)
  try {
    const r = await runPythonCore(['install-sentinels'], 20_000)
    steps.push(['sentinels', r.code === 0 ? '已生成/刷新' : `rc=${r.code} ${r.err.slice(0, 80)}`])
  } catch (e) {
    steps.push(['sentinels', `失败: ${e.message}`])
  }

  // 4. trust 引导(仅提示;modified 阻断在 CLI emit 层)
  try {
    const r = await runPythonCore(['check'], 15_000)
    steps.push(['trust', r.out.includes('untracked') || !r.out
      ? 'untracked — 建议 dsh-suite trust 固化当前配置'
      : '状态见 dsh-suite status'])
  } catch { /* 忽略 */ }

  for (const [k, v] of steps) console.log(`[security-suite] 自举 · ${k}: ${v}`)
}

// ── 插件入口 ────────────────────────────────────────────────────────────────

export async function apply(ctx, config) {
  const cfg = { ...DEFAULTS, ...(config || {}) }
  const launcher = resolveLauncher(cfg)

  if (!launcher) {
    console.warn('[security-suite] 未找到 Python 核心(异常: 包内 python/ 缺失),空转运行')
    return
  }

  // 自举异步执行,不阻塞插件加载;失败降级为纯拦截层
  bootstrap().catch((e) => console.warn('[security-suite] 自举部分失败(不影响拦截):', e.message))

  let consecFails = 0
  let breakerUntil = 0
  const breakerOpen = () => consecFails >= cfg.breakerThreshold && Date.now() < breakerUntil
  function noteFailure(e) {
    consecFails += 1
    if (consecFails === cfg.breakerThreshold) {
      breakerUntil = Date.now() + cfg.breakerResetMs
      console.warn(`[security-suite] 连续失败 ${consecFails} 次,熔断 ${cfg.breakerResetMs / 1000}s`
        + `(fail-${cfg.failOpen ? 'open' : 'closed'})。最近错误: ${e.message}`)
    }
  }

  ctx.effect(() => ctx.on('tools/pre-execute', async (exec, next) => {
    if (breakerOpen()) return next()
    try {
      const r = await emitEvent(launcher, 'PreToolUse', buildEnvelope(exec), cfg.preTimeoutMs)
      consecFails = 0
      if (r.allowed === false || r.exitCode === 2) {
        return { kind: 'deny', reason: r.reason || 'dsh-security-suite 总线拦截' }
      }
    } catch (e) {
      noteFailure(e)
      if (!cfg.failOpen) return { kind: 'deny', reason: `扫描器不可用(fail-closed): ${e.message}` }
    }
    return next()
  }), 'dsh-security-suite: pre-execute')

  ctx.effect(() => ctx.on('tools/post-execute', async (exec, result, next) => {
    const decision = await next()
    if (!breakerOpen()) {
      emitEvent(launcher, 'PostToolUse',
        buildEnvelope(exec, { ok: result?.isError === false }),
        cfg.postTimeoutMs).catch(() => {})
    }
    return decision
  }), 'dsh-security-suite: post-execute')

  console.log(`[security-suite] 已挂载 tools/pre+post-execute → dsh-hooks 总线`
    + `(launcher=${launcher.argv.join(' ')}, fail-${cfg.failOpen ? 'open' : 'closed'})`)
}
