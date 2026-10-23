#!/usr/bin/env node
// Vuln repro results dashboard.
//
// Read-only case data from data/cases/*.json plus a real, whitelisted exploit
// runner. The runner never accepts arbitrary commands from the client: each
// target maps to a fixed argv that this file owns, and the only client-supplied
// input is a target key that must exist in TARGETS.

import { createServer } from 'node:http'
import { readFile, readdir } from 'node:fs/promises'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, join, resolve } from 'node:path'
import { randomUUID } from 'node:crypto'
import { openShell, sweepStaleShells } from './shell-backends.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
// The lab checkouts live outside this repo, so their location must not be
// baked in: VULN_REPRO_LABS points at the directory holding the lab folders.
// Defaults to the parent of this repo, which is where the reference labs sit.
const WORKSPACE = process.env.VULN_REPRO_LABS
  ? resolve(process.env.VULN_REPRO_LABS)
  : resolve(HERE, '..', '..')
const CASES_DIR = join(HERE, 'data', 'cases')
const WEB_DIR = join(HERE, 'web')
const HOST = '127.0.0.1'
const PORT = Number(process.env.PORT || 3010)

// Fixed targets. `argv` is the complete command line, built here and never from
// request input. `shellMode` selects which backend gives the interactive prompt
// (see shell-backends.mjs): `webshell` drops a persistent PHP shell into the
// lab's writable bind mount, `rce` re-runs the exploit per command.
const TARGETS = {
  'sp-clean': {
    label: 'sp-8234 — php:8.2.34-apache (cleanup=0)',
    container: 'sp-8234',
    url: 'http://127.0.0.1:19234',
    shellMode: 'webshell',
    argv: [
      'python3', join(WORKSPACE, 'session-poison-lab', 'scripts', 'exp_session_poison.py'),
      'http://127.0.0.1:19234',
      '--sink', '/sink.php?page=',
      '--save-path', '/tmp',
      '--cmd', 'id'
    ],
    shell: /uid=33\(www-data\)|PWNED:/
  },
  'sp-hard': {
    label: 'sp-hard — php:8.2.34-apache (cleanup=1 + strict=1, 竞态)',
    container: 'sp-hard',
    url: 'http://127.0.0.1:19650',
    shellMode: 'webshell',
    argv: [
      'python3', join(WORKSPACE, 'session-poison-lab', 'scripts', 'exp_session_poison.py'),
      '--race',
      'http://127.0.0.1:19650',
      '--sink', '/sink.php?page=',
      '--cmd', 'id'
    ],
    shell: /uid=33\(www-data\)/
  },
  'php2shell-base': {
    label: 'cve-target — php:8.4.26-apache (漏洞版)',
    container: 'cve-target',
    url: 'http://127.0.0.1:18110/index.php',
    runExp: join(WORKSPACE, 'php2shell-lab', 'cve-rce', 'run_exp.sh'),
    labKey: 'base',
    argv: ['bash', join(WORKSPACE, 'php2shell-lab', 'cve-rce', 'run_exp.sh'), 'id', 'base'],
    shell: /uid=33\(www-data\)/
  },
  'php2shell-fixed': {
    label: 'cve-fixed — php:8.4.27-apache (修复对照，预期失败)',
    container: 'cve-fixed',
    url: 'http://127.0.0.1:18111/index.php',
    // Deliberately no shell backend: the exploit fails here, so there is no
    // channel to hold a prompt with. Reporting that honestly is the point of
    // the control.
    demoOnly: true,
    runExp: join(WORKSPACE, 'php2shell-lab', 'cve-rce', 'run_exp.sh'),
    labKey: 'fixed',
    argv: ['bash', join(WORKSPACE, 'php2shell-lab', 'cve-rce', 'run_exp.sh'), 'id', 'fixed'],
    shell: /uid=33\(www-data\)/
  },

  // React2Shell (CVE-2025-55182). The lab owns its own runners; the exploit
  // writes proof into the target container, so success is judged by the
  // runner's verdict rather than an HTTP status (a poisoned thenable hangs the
  // response — that is a symptom, not evidence).
  'r2s-next-1554': {
    label: 'r2s-next-1554-noaction — next@15.5.4 (漏洞版)',
    container: 'r2s-next-1554-noaction',
    url: 'http://127.0.0.1:19401/',
    shellMode: 'r2s',
    labDir: join(WORKSPACE, 'react2shell-lab'),
    shellPort: '19401',
    argv: [
      'python3', join(WORKSPACE, 'react2shell-lab', 'scripts', 'r2s_shell.py'),
      '--port', '19401', '--container', 'r2s-next-1554-noaction', 'check'
    ],
    shell: /uid=0\(root\)|uid=\d+/
  },
  'r2s-next-1557': {
    label: 'r2s-next-1557-noaction — next@15.5.7 (修复对照，预期失败)',
    container: 'r2s-next-1557-noaction',
    url: 'http://127.0.0.1:19405/',
    // Patched: no channel exists, so no shell backend. Same rule as the PHP fix.
    demoOnly: true,
    labDir: join(WORKSPACE, 'react2shell-lab'),
    shellPort: '19405',
    argv: [
      'python3', join(WORKSPACE, 'react2shell-lab', 'scripts', 'r2s_shell.py'),
      '--port', '19405', '--container', 'r2s-next-1557-noaction', 'check'
    ],
    shell: /uid=0\(root\)/
  }
}

// One exploit at a time: these routines are timing- and heap-layout-sensitive,
// so concurrent runs against the same lab would corrupt each other's result.
let busy = false

// Live interactive shell sessions, keyed by an opaque id.
const SHELLS = new Map()

function readBody (req, limit = 4096) {
  return new Promise((resolvePromise) => {
    let raw = ''
    let tooLarge = false
    req.on('data', (c) => {
      if (tooLarge) return
      raw += c
      if (raw.length > limit) {
        tooLarge = true
        resolvePromise({ ok: false, error: 'body too large' })
      }
    })
    req.on('end', () => {
      if (tooLarge) return
      try {
        resolvePromise({ ok: true, value: JSON.parse(raw || '{}') })
      } catch {
        resolvePromise({ ok: false, error: 'bad json' })
      }
    })
    req.on('error', () => resolvePromise({ ok: false, error: 'read error' }))
  })
}

function json (res, code, body) {
  const payload = JSON.stringify(body)
  res.writeHead(code, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload)
  })
  res.end(payload)
}

// Case files are added by hand as a run finishes, so a broken file must never
// take the whole dashboard down: collect problems and keep serving the rest.
async function loadCases () {
  const files = (await readdir(CASES_DIR)).filter((f) => f.endsWith('.json')).sort()
  const cases = []
  const problems = []

  for (const file of files) {
    try {
      const parsed = JSON.parse(await readFile(join(CASES_DIR, file), 'utf8'))
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        problems.push({ file, error: '顶层必须是 JSON 对象' })
        continue
      }
      if (!parsed.id) {
        problems.push({ file, error: '缺少必填字段 id' })
        continue
      }
      if (!parsed.title) parsed.title = parsed.id
      cases.push({ ...parsed, _file: file })
    } catch (err) {
      problems.push({ file, error: 'JSON 解析失败: ' + err.message })
    }
  }
  return { cases, problems }
}

function dockerState (container) {
  return new Promise((resolvePromise) => {
    const child = spawn('docker', ['inspect', '-f', '{{.State.Status}}', container], {
      stdio: ['ignore', 'pipe', 'pipe']
    })
    let out = ''
    child.stdout.on('data', (c) => { out += c })
    child.on('error', () => resolvePromise('unavailable'))
    child.on('close', () => resolvePromise(out.trim() || 'missing'))
  })
}

function streamRun (res, targetKey) {
  const target = TARGETS[targetKey]
  res.writeHead(200, {
    'content-type': 'text/event-stream; charset=utf-8',
    'cache-control': 'no-cache, no-transform',
    connection: 'keep-alive',
    'x-accel-buffering': 'no'
  })
  const send = (event, data) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
  send('meta', { target: targetKey, label: target.label, url: target.url })

  const child = spawn(target.argv[0], target.argv.slice(1), {
    cwd: WORKSPACE,
    env: { ...process.env, PYTHONUNBUFFERED: '1' },
    stdio: ['ignore', 'pipe', 'pipe']
  })

  let output = ''
  let finished = false
  const forward = (chunk) => {
    output += chunk
    for (const line of chunk.split('\n')) {
      if (line.trim()) send('line', { text: line })
    }
  }
  child.stdout.on('data', (c) => forward(String(c)))
  child.stderr.on('data', (c) => forward(String(c)))

  const timer = setTimeout(() => {
    if (!finished) child.kill('SIGKILL')
  }, 180000)

  const done = (code, reason) => {
    if (finished) return
    finished = true
    clearTimeout(timer)
    busy = false
    const gotShell = target.shell.test(output)
    send('done', {
      code,
      reason,
      gotShell,
      verdict: gotShell ? 'shell' : (code === 0 ? 'no-shell' : 'failed')
    })
    res.end()
  }

  child.on('error', (err) => {
    send('line', { text: `[dashboard] 无法启动子进程: ${err.message}` })
    done(-1, 'spawn-error')
  })
  child.on('close', (code, signal) => {
    done(code, signal ? `signal:${signal}` : 'exit')
  })

  res.on('close', () => {
    if (!finished) child.kill('SIGKILL')
  })
}

async function serveStatic (res, pathname) {
  const rel = pathname === '/' ? 'index.html' : pathname.slice(1)
  const file = join(WEB_DIR, rel)
  if (!file.startsWith(WEB_DIR)) return json(res, 403, { error: 'forbidden' })
  try {
    const body = await readFile(file)
    const type = file.endsWith('.html') ? 'text/html; charset=utf-8'
      : file.endsWith('.css') ? 'text/css; charset=utf-8'
        : file.endsWith('.js') ? 'application/javascript; charset=utf-8'
          : 'application/octet-stream'
    res.writeHead(200, { 'content-type': type, 'content-length': body.length })
    res.end(body)
  } catch {
    json(res, 404, { error: 'not found' })
  }
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${HOST}:${PORT}`)
  const { pathname } = url

  try {
    if (pathname === '/api/cases') {
      const { cases, problems } = await loadCases()
      return json(res, 200, { cases, problems })
    }

    if (pathname.startsWith('/api/cases/')) {
      const id = pathname.split('/')[3]
      const found = (await loadCases()).cases.find((c) => c.id === id)
      return found ? json(res, 200, found) : json(res, 404, { error: 'unknown case' })
    }

    if (pathname === '/api/targets') {
      const entries = await Promise.all(Object.entries(TARGETS).map(async ([key, t]) => ({
        key, label: t.label, url: t.url, container: t.container, state: await dockerState(t.container)
      })))
      return json(res, 200, { busy, targets: entries })
    }

    if (pathname === '/api/run') {
      if (req.method !== 'POST') return json(res, 405, { error: 'POST required' })
      if (busy) return json(res, 409, { error: '已有一次利用正在执行，请等待完成' })
      const parsed = await readBody(req)
      if (!parsed.ok) return json(res, 400, { error: parsed.error })
      const targetKey = parsed.value.target
      if (!Object.hasOwn(TARGETS, targetKey)) return json(res, 400, { error: 'unknown target' })

      const state = await dockerState(TARGETS[targetKey].container)
      if (state !== 'running') {
        return json(res, 409, {
          error: `靶场容器 ${TARGETS[targetKey].container} 未运行（当前状态: ${state}）`,
          hint: targetKey.startsWith('php2shell')
            ? '先执行: bash php2shell-lab/cve-rce/lab_up.sh base'
            : '先执行: bash session-poison-lab/scripts/sp_lab_up.sh'
        })
      }

      busy = true
      req.setTimeout(0)
      return streamRun(res, targetKey)
    }

    // ---- interactive shell sessions ----
    if (pathname === '/api/shell/open') {
      if (req.method !== 'POST') return json(res, 405, { error: 'POST required' })
      const payload = await readBody(req)
      if (!payload.ok) return json(res, 400, { error: payload.error })
      const targetKey = payload.value.target
      if (!Object.hasOwn(TARGETS, targetKey)) return json(res, 400, { error: 'unknown target' })
      const target = TARGETS[targetKey]

      if (target.demoOnly) {
        return json(res, 409, {
          error: `${target.label} 是修复对照，利用不成立，没有可用的 shell 通道`,
          hint: '对照目标只提供 EXP 演示（预期失败），不提供交互式 shell。'
        })
      }

      const state = await dockerState(target.container)
      if (state !== 'running') {
        return json(res, 409, {
          error: `靶场容器 ${target.container} 未运行（当前状态: ${state}）`,
          hint: targetKey.startsWith('php2shell')
            ? '先执行: bash php2shell-lab/cve-rce/lab_up.sh base'
            : '先执行: bash session-poison-lab/scripts/sp_lab_up.sh'
        })
      }

      try {
        const backend = await openShell(target)
        const id = randomUUID()
        SHELLS.set(id, { backend, targetKey, createdAt: Date.now() })
        const banner = backend.kind === 'webshell'
          ? `已部署 webshell 并验证可用（${target.container}）`
          : `无持久 webshell 可用，改用逐命令执行（${target.container}）—— 每条命令会重跑利用，但不保留 cd/env 状态`
        return json(res, 200, {
          id,
          kind: backend.kind,
          banner,
          target: targetKey,
          label: target.label
        })
      } catch (err) {
        return json(res, 500, { error: `建立 shell 失败: ${err.message}` })
      }
    }

    if (pathname === '/api/shell/exec') {
      if (req.method !== 'POST') return json(res, 405, { error: 'POST required' })
      const payload = await readBody(req, 65536)
      if (!payload.ok) return json(res, 400, { error: payload.error })
      const { id, cmd } = payload.value || {}
      const session = SHELLS.get(id)
      if (!session) return json(res, 404, { error: 'shell 会话不存在或已过期' })
      if (typeof cmd !== 'string' || !cmd.trim()) return json(res, 400, { error: 'cmd 不能为空' })
      if (cmd.length > 4000) return json(res, 400, { error: 'cmd 过长' })

      try {
        const started = Date.now()
        const { output, code } = await session.backend.exec(cmd)
        return json(res, 200, { output, code, ms: Date.now() - started })
      } catch (err) {
        return json(res, 500, { error: `执行失败: ${err.message}` })
      }
    }

    if (pathname === '/api/shell/close') {
      if (req.method !== 'POST') return json(res, 405, { error: 'POST required' })
      const payload = await readBody(req)
      if (!payload.ok) return json(res, 400, { error: payload.error })
      const session = SHELLS.get(payload.value.id)
      if (session) {
        await session.backend.close().catch(() => {})
        SHELLS.delete(payload.value.id)
      }
      return json(res, 200, { closed: true })
    }

    if (pathname === '/healthz') return json(res, 200, { ok: true })

    return serveStatic(res, pathname)
  } catch (err) {
    return json(res, 500, { error: String(err && err.message ? err.message : err) })
  }
})

server.listen(PORT, HOST, async () => {
  console.log(`[dashboard] http://${HOST}:${PORT}`)
  // Clear any shell a previous run left in a lab's bind-mounted docroot.
  const containers = Object.values(TARGETS)
    .filter((t) => t.shellMode === 'webshell')
    .map((t) => t.container)
  await sweepStaleShells([...new Set(containers)])
  console.log('[dashboard] stale shell sweep done')
})
