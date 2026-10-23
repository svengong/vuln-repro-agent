'use strict'

const state = { cases: [], problems: [], activeId: null, targets: {}, busy: false, running: false }

const $ = (sel) => document.querySelector(sel)
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))

const STATUS_TEXT = { hit: '打穿', miss: '未命中', 'control-fail': '对照失败(预期)', unevaluated: '未能评估' }

/* ---------- data ---------- */

async function loadCases () {
  const res = await fetch('/api/cases')
  const data = await res.json()
  state.cases = data.cases || []
  state.problems = data.problems || []
  renderProblems()
  renderCaseList()
  if (!state.cases.length) return
  const fromHash = location.hash.replace('#', '')
  selectCase(fromHash && state.cases.some((c) => c.id === fromHash) ? fromHash : state.cases[0].id)
}

/** Tell the user which case files failed to load, and why. */
function renderProblems () {
  let box = $('#caseProblems')
  if (!state.problems.length) {
    if (box) box.remove()
    return
  }
  if (!box) {
    box = document.createElement('div')
    box.id = 'caseProblems'
    box.className = 'case-problems'
    $('#caseList').after(box)
  }
  box.innerHTML = '<div class="cp-title">以下案例文件加载失败</div>' +
    state.problems.map((p) =>
      `<div class="cp-row"><code>${esc(p.file)}</code><span>${esc(p.error)}</span></div>`).join('')
}

function renderCaseList () {
  const nav = $('#caseList')
  nav.innerHTML = ''
  for (const c of state.cases) {
    const btn = document.createElement('button')
    btn.className = 'case-item' + (c.id === state.activeId ? ' active' : '')
    btn.dataset.id = c.id
    btn.innerHTML = `<span class="t">${esc(c.title.split('—')[0].trim())}</span>
      <span class="muted small">${c.hasCve ? esc(c.cves.join(' / ')) : '无 CVE'}</span>`
    btn.addEventListener('click', () => selectCase(c.id))
    nav.appendChild(btn)
  }
}

function selectCase (id) {
  if (!id) return
  state.activeId = id
  location.hash = id
  renderCaseList()
  const c = state.cases.find((x) => x.id === id)
  $('#hero').hidden = true
  const view = $('#caseView')
  view.hidden = false
  view.innerHTML = renderCase(c)
  mountDemo(c)
}

/* ---------- render ---------- */

/** Fill in defaults so a new, partially-written case JSON still renders. */
function normalizeCase (c) {
  const arr = (v) => (Array.isArray(v) ? v : [])
  const d = c && typeof c === 'object' ? c : {}
  return {
    id: d.id || 'unnamed',
    title: d.title || d.id || '未命名案例',
    subtitle: d.subtitle || '',
    kind: d.kind || '',
    cves: arr(d.cves),
    hasCve: d.hasCve === true || arr(d.cves).length > 0,
    severity: d.severity && typeof d.severity === 'object' ? d.severity : {},
    baseline: d.baseline || '',
    stages: arr(d.stages),
    products: arr(d.products),
    productsSummary: d.productsSummary && typeof d.productsSummary === 'object' ? d.productsSummary : {},
    limits: arr(d.limits),
    demo: d.demo && typeof d.demo === 'object' ? d.demo : {}
  }
}

function renderCase (raw) {
  const c = normalizeCase(raw)
  const sev = c.severity
  const cveBadges = c.hasCve
    ? c.cves.map((x) => `<span class="badge cve">${esc(x)}</span>`).join('')
    : '<span class="badge nocve">无公开 CVE</span>'
  const ps = c.productsSummary

  return `
  <div class="case-header">
    <h1>${esc(c.title)}</h1>
    <div class="muted">${esc(c.subtitle || '')} · ${esc(c.kind || '')}</div>
    <div class="badges">
      ${cveBadges}
      <span class="badge crit">CVSS v3.1 ${sev.v31} / v4.0 ${sev.v40}</span>
      <span class="badge">${esc(sev.label || '')}</span>
    </div>
    ${c.baseline ? `<div class="baseline">${esc(c.baseline)}</div>` : ''}
  </div>

  <div class="section-title">
    <h2>复现流程（S1–S7）</h2>
    <span class="sum">${c.stages.length} 个阶段 · ${c.stages.filter((s) => s.status === 'done').length} 已完成</span>
  </div>
  <div class="pipeline">
    ${c.stages.map((s) => `
      <div class="stage ${s.status}">
        <div class="stage-rail"><div class="stage-id">${esc(s.id)}</div><div class="stage-line"></div></div>
        <div class="stage-body">
          <div class="stage-name">${esc(s.name)}</div>
          <div class="stage-summary">${esc(s.summary || '')}</div>
          <ul class="stage-evidence">${(s.evidence || []).map((e) => `<li>${esc(e)}</li>`).join('')}</ul>
        </div>
      </div>`).join('')}
  </div>

  <div class="section-title">
    <h2>产品 / 版本矩阵</h2>
    <span class="sum">${ps.note || ''}</span>
  </div>
  <div class="summary-chips">
    <div class="chip"><b>${ps.attempted ?? c.products.length}</b>尝试</div>
    <div class="chip"><b style="color:var(--hit)">${ps.hit ?? 0}</b>打穿</div>
    ${ps.miss != null ? `<div class="chip"><b style="color:var(--miss)">${ps.miss}</b>未命中</div>` : ''}
    ${ps.controlFail ? `<div class="chip"><b style="color:var(--accent)">${ps.controlFail}</b>修复对照</div>` : ''}
    ${ps.unevaluated ? `<div class="chip"><b style="color:var(--unknown)">${ps.unevaluated}</b>未能评估</div>` : ''}
  </div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>产品</th><th>镜像 / 版本</th><th>运行时</th><th>结论</th><th>说明</th></tr></thead>
      <tbody>
        ${c.products.map((p) => `
          <tr>
            <td>${esc(p.name)}</td>
            <td class="img">${esc(p.image)}</td>
            <td class="img">${esc(p.runtime)}</td>
            <td><span class="pill ${esc(p.status)}">${esc(STATUS_TEXT[p.status] || p.status)}</span></td>
            <td>${esc(p.result)}</td>
          </tr>`).join('')}
      </tbody>
    </table>
  </div>

  <div class="section-title"><h2>能力边界（诚实声明）</h2></div>
  <ul class="limits">${(c.limits || []).map((l) => `<li>${esc(l)}</li>`).join('')}</ul>
  `
}

function targetUrl (key) {
  const t = state.targets[key]
  return t ? t.url : ''
}

/* ---------- targets ---------- */

async function loadTargets () {
  try {
    const res = await fetch('/api/targets')
    const data = await res.json()
    state.busy = data.busy
    state.targets = {}
    const list = $('#targetList')
    list.innerHTML = ''
    for (const t of data.targets) {
      state.targets[t.key] = t
      const row = document.createElement('div')
      row.className = 'target-row'
      row.innerHTML = `<span class="st ${esc(t.state)}"></span>
        <span title="${esc(t.label)}">${esc(t.container)} <span class="muted">${esc(t.state)}</span></span>`
      list.appendChild(row)
    }
    const running = data.targets.filter((t) => t.state === 'running').length
    $('#targetsState').textContent = `${running}/${data.targets.length} 靶场运行中`
  } catch {
    $('#targetsState').textContent = '靶场状态不可用'
  }
}

/* ---------- demo side panel: host pseudo-shell -> victim shell ---------- */

// Two phases, in order:
//   host   — a pseudo-shell on the attacker host. No manual input; the only
//            action is "run exp". This models the real situation: you are on
//            your own box, not yet on the target.
//   victim — the real shell on the compromised host, unlocked only after the
//            exp actually succeeds. Manual input works here.
const demo = {
  phase: 'idle',        // idle | host | victim
  caseId: null,
  targetKey: null,
  shellId: null,
  kind: null,
  runningExp: false,
  pendingCmd: false
}

const PHASE_TEXT = {
  idle: '未连接',
  host: '宿主机伪 shell',
  victim: '受害者 shell'
}

function setPhaseDot () {
  const d = $('#phaseDot')
  d.className = 'live-dot' +
    (demo.phase === 'victim' ? ' on' : demo.phase === 'host' ? ' busy' : '')
}

function appendTerm (text, cls) {
  const out = $('#termOut')
  const div = document.createElement('div')
  if (cls) div.className = cls
  div.textContent = text
  out.appendChild(div)
  out.scrollTop = out.scrollHeight
}

function showVerdict (kind, text) {
  const v = $('#verdict')
  v.className = 'verdict ' + kind
  v.textContent = text
  v.hidden = false
}

function clearVerdict () {
  const v = $('#verdict')
  v.hidden = true
  v.textContent = ''
}

/** Enter the host pseudo-shell for the active case (does NOT run the exp). */
function enterHostPhase (rawCase) {
  const c = normalizeCase(rawCase)
  demo.caseId = c.id
  demo.targetKey = c.demo.targetKey || null
  demo.phase = 'host'
  demo.shellId = null
  demo.kind = null

  $('#demoTargetLabel').textContent = c.demo.targetLabel || ''
  $('#term').hidden = false
  $('#termOut').innerHTML = ''
  $('#hostRow').hidden = false
  $('#victimRow').hidden = true
  const hasTarget = !!demo.targetKey
  $('#expBtn').disabled = !hasTarget
  $('#expBtn').textContent = '▶ 执行 exp'
  $('#hostNote').textContent = hasTarget
    ? '宿主机伪 shell：不可手动输入'
    : '该案例未配置可执行靶场（demo.targetKey 缺失）'
  $('#demoReset').disabled = false
  clearVerdict()
  setPhaseDot()

  appendTerm(`[host] 已连接到宿主机（攻击方），目标: ${c.demo.targetLabel || '未配置'}`, 'e-sys')
  appendTerm('[host] 这是一个伪 shell：本阶段只能点击「执行 exp」，不支持手动输入。', 'e-sys')
  appendTerm('[host] 执行成功后才会进入受害者的正常 shell。', 'e-sys')
  appendTerm('', null)

  $('#demoHint').innerHTML =
    '当前在<b>宿主机伪 shell</b>（攻击方）。点击「执行 exp」发起利用；成功后自动进入受害 shell。'
}

/** Run the exploit; on success switch to the victim shell. */
async function runExp () {
  if (demo.runningExp || demo.phase !== 'host') return
  demo.runningExp = true
  const btn = $('#expBtn')
  btn.disabled = true
  btn.textContent = '执行中…'
  clearVerdict()
  setPhaseDot()

  appendTerm(`$ ./exp.sh --target ${demo.targetKey}`, 'e-cmd')

  try {
    const res = await fetch('/api/run', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ target: demo.targetKey })
    })

    if (!res.ok || !res.body) {
      const err = await res.json().catch(() => ({ error: 'unknown error' }))
      appendTerm('[dashboard] ' + (err.error || res.status), 'e-err')
      if (err.hint) appendTerm('[dashboard] ' + err.hint, 'e-sys')
      showVerdict('failed', '未能启动利用：' + (err.error || '未知错误'))
      btn.disabled = false
      btn.textContent = '▶ 重试 exp'
      return
    }

    const reader = res.body.getReader()
    const decoder = new TextDecoder()
    let buffer = ''
    let gotShell = false

    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })
      const frames = buffer.split('\n\n')
      buffer = frames.pop()
      for (const frame of frames) {
        const ev = handleExpFrame(frame)
        if (ev === 'shell') gotShell = true
      }
    }

    if (gotShell) {
      showVerdict('shell', '✅ exp 成功 — 已进入受害者 shell，可手动执行命令')
      await enterVictimPhase()
    } else {
      showVerdict('no-shell',
        '利用未取得 shell。宿主伪 shell 保持可用，可重试或查看上方输出。')
      btn.disabled = false
      btn.textContent = '▶ 重试 exp'
    }
  } catch (err) {
    appendTerm('[dashboard] 连接中断: ' + err.message, 'e-err')
    showVerdict('failed', '连接中断')
    btn.disabled = false
    btn.textContent = '▶ 重试 exp'
  } finally {
    demo.runningExp = false
    setPhaseDot()
  }
}

function handleExpFrame (frame) {
  const lines = frame.split('\n')
  const ev = lines.find((l) => l.startsWith('event: '))
  const dataLine = lines.find((l) => l.startsWith('data: '))
  if (!ev || !dataLine) return null
  const event = ev.slice(7)
  let data
  try { data = JSON.parse(dataLine.slice(6)) } catch { return null }

  if (event === 'line') {
    const hit = /uid=33|PWNED|www-data/.test(data.text)
    appendTerm('  ' + data.text, hit ? 'l-hit' : null)
  } else if (event === 'done') {
    return data.gotShell ? 'shell' : null
  }
  return null
}

/** Unlock the victim shell after a confirmed successful exploit. */
async function enterVictimPhase () {
  try {
    const res = await fetch('/api/shell/open', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ target: demo.targetKey })
    })
    const data = await res.json()
    if (!res.ok) {
      appendTerm('[dashboard] ' + (data.error || '打开受害者 shell 失败'), 'e-err')
      if (data.hint) appendTerm('[dashboard] ' + data.hint, 'e-sys')
      return
    }

    demo.shellId = data.id
    demo.kind = data.kind
    demo.phase = 'victim'

    appendTerm('', null)
    appendTerm('─'.repeat(46), 'e-sys')
    appendTerm(`[victim] 已进入受害者 shell — ${data.banner}`, 'e-sys')
    appendTerm('[victim] 现在可以手动输入命令（id、pwd、ls / …）；输入 exit 退出。', 'e-sys')
    appendTerm('', null)

    $('#hostRow').hidden = true
    $('#victimRow').hidden = false
    $('#demoHint').innerHTML =
      demo.kind === 'webshell'
        ? '已进入<b>受害者 shell</b>：命令毫秒级响应，但 <b>cd/env 不跨命令保留</b>。'
        : '已进入<b>受害者 shell</b>（逐命令 RCE）：每条命令重跑利用，<b>不保留 cd/env</b>。'
    setPhaseDot()
    $('#termInput').focus()
  } catch (err) {
    appendTerm('[dashboard] 打开受害者 shell 异常: ' + err.message, 'e-err')
  }
}

async function runVictimCommand (cmd) {
  if (demo.phase !== 'victim' || !demo.shellId) return
  appendTerm('victim$ ' + cmd, 'e-cmd')
  demo.pendingCmd = true
  setPhaseDot()

  try {
    const res = await fetch('/api/shell/exec', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id: demo.shellId, cmd })
    })
    const data = await res.json()
    if (!res.ok) {
      appendTerm('[dashboard] ' + (data.error || '执行失败'), 'e-err')
      return
    }
    if (data.output) appendTerm(data.output, null)
    else appendTerm('(无输出)', 'e-sys')
    if (data.code) appendTerm(`[exit ${data.code}]`, 'e-err')
    if (data.ms != null) appendTerm(`[${data.ms} ms]`, 'e-sys')
  } catch (err) {
    appendTerm('[dashboard] 执行异常: ' + err.message, 'e-err')
  } finally {
    demo.pendingCmd = false
    setPhaseDot()
  }
}

async function resetDemo () {
  if (demo.shellId) {
    await fetch('/api/shell/close', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id: demo.shellId })
    }).catch(() => {})
  }
  demo.shellId = null
  demo.kind = null
  demo.phase = 'idle'
  $('#term').hidden = true
  $('#termOut').innerHTML = ''
  $('#hostRow').hidden = false
  $('#victimRow').hidden = true
  $('#expBtn').disabled = true
  $('#expBtn').textContent = '▶ 执行 exp'
  $('#demoReset').disabled = true
  clearVerdict()
  setPhaseDot()

  const c = state.cases.find((x) => x.id === state.activeId)
  if (c) enterHostPhase(c)
}

/** Point the demo panel at a case, resetting any previous session. */
async function mountDemo (c) {
  if (demo.shellId) {
    await fetch('/api/shell/close', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id: demo.shellId })
    }).catch(() => {})
  }
  demo.shellId = null
  demo.phase = 'idle'
  enterHostPhase(c)
}

function wireDemo () {
  $('#expBtn').addEventListener('click', runExp)
  $('#demoReset').addEventListener('click', resetDemo)

  const input = $('#termInput')
  input.addEventListener('keydown', async (e) => {
    if (e.key !== 'Enter') return
    const cmd = input.value.trim()
    if (!cmd || demo.pendingCmd) return
    input.value = ''
    if (cmd === 'exit' || cmd === 'quit') {
      await resetDemo()
      return
    }
    await runVictimCommand(cmd)
    input.focus()
  })

  window.addEventListener('beforeunload', () => {
    if (demo.shellId) {
      fetch('/api/shell/close', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ id: demo.shellId }), keepalive: true
      }).catch(() => {})
    }
  })
}

/* ---------- resizable demo panel ---------- */

const PANEL_MIN = 320
const PANEL_MAX = 900
const PANEL_KEY = 'vuln-dashboard.panelWidth'

function panelBounds () {
  // Never let the panel eat the reading column: keep at least ~420px for it.
  const total = window.innerWidth
  const leftCol = total > 1240 ? 250 : 0
  const maxByViewport = Math.max(PANEL_MIN, total - leftCol - 420)
  return { min: PANEL_MIN, max: Math.min(PANEL_MAX, maxByViewport) }
}

function applyPanelWidth (px) {
  const { min, max } = panelBounds()
  const w = Math.round(Math.min(max, Math.max(min, px)))
  document.documentElement.style.setProperty('--demo-w', w + 'px')
  try { localStorage.setItem(PANEL_KEY, String(w)) } catch {}
  return w
}

function restorePanelWidth () {
  let saved = null
  try { saved = Number(localStorage.getItem(PANEL_KEY)) } catch {}
  const { min, max } = panelBounds()
  applyPanelWidth(saved && Number.isFinite(saved) ? saved : Math.min(max, 460))
}

function wireResizer () {
  const bar = $('#demoResizer')
  if (!bar) return
  let dragging = false

  const onDown = (e) => {
    dragging = true
    bar.classList.add('dragging')
    document.body.classList.add('resizing')
    bar.setPointerCapture?.(e.pointerId)
    e.preventDefault()
  }
  const onMove = (e) => {
    if (!dragging) return
    applyPanelWidth(window.innerWidth - e.clientX)
  }
  const onUp = (e) => {
    if (!dragging) return
    dragging = false
    bar.classList.remove('dragging')
    document.body.classList.remove('resizing')
    bar.releasePointerCapture?.(e.pointerId)
  }

  bar.addEventListener('pointerdown', onDown)
  window.addEventListener('pointermove', onMove)
  window.addEventListener('pointerup', onUp)

  // Double-click restores the default width.
  bar.addEventListener('dblclick', () => applyPanelWidth(460))

  // Keyboard: arrows nudge, for accessibility without a mouse.
  bar.addEventListener('keydown', (e) => {
    const cur = parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--demo-w')) || 460
    if (e.key === 'ArrowLeft') { applyPanelWidth(cur + 24); e.preventDefault() }
    if (e.key === 'ArrowRight') { applyPanelWidth(cur - 24); e.preventDefault() }
  })

  window.addEventListener('resize', () => {
    const cur = parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--demo-w')) || 460
    applyPanelWidth(cur)
  })

  restorePanelWidth()
}

/* ---------- boot ---------- */

window.addEventListener('hashchange', () => {
  const id = location.hash.replace('#', '')
  if (id && id !== state.activeId) selectCase(id)
})

wireDemo()
wireResizer()
loadCases()
loadTargets()
setInterval(loadTargets, 5000)
