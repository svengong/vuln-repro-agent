// Renders the dashboard in jsdom against the live server and asserts that the
// page actually produced its content — case cards, stage timeline, product
// table, and the demo control. This is the browser-substitute check: it runs
// the real app.js against real API responses.
// jsdom is only needed for these browser-level checks, so resolve it from a
// few likely locations instead of hard-coding one machine's path. Skipping is
// explicit: a missing jsdom prints how to get it rather than crashing.
const jsdomCandidates = [
  process.env.JSDOM_PATH,
  'jsdom',
  new URL('./node_modules/jsdom/lib/api.js', import.meta.url).pathname,
  new URL('../node_modules/jsdom/lib/api.js', import.meta.url).pathname,
]

let JSDOM
for (const cand of jsdomCandidates) {
  if (!cand) continue
  try {
    ({ JSDOM } = await import(cand))
    break
  } catch {}
}

if (!JSDOM) {
  console.error('[skip] 需要 jsdom 才能跑渲染检查：npm i -D jsdom，或设置 JSDOM_PATH 指向 jsdom/lib/api.js')
  process.exit(0)
}
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'

const BASE = process.env.BASE || 'http://127.0.0.1:3010'
const WEB = new URL('./web', import.meta.url).pathname

const html = await readFile(join(WEB, 'index.html'), 'utf8')
const dom = new JSDOM(html, { url: BASE + '/', runScripts: 'outside-only', pretendToBeVisual: true })
const { window } = dom

// jsdom has no fetch; give it the real one from Node.
window.fetch = (input, init) => fetch(new URL(input, BASE), init)
window.TextDecoder = TextDecoder

const appSrc = await readFile(join(WEB, 'app.js'), 'utf8')
window.eval(appSrc)

const wait = (ms) => new Promise((r) => setTimeout(r, ms))

let failures = 0
const check = (name, cond, detail = '') => {
  if (cond) console.log(`  PASS  ${name}`)
  else { console.log(`  FAIL  ${name} ${detail}`); failures++ }
}

// Wait for the initial loadCases()/loadTargets() round trips to settle.
for (let i = 0; i < 40; i++) {
  if (window.document.querySelectorAll('.case-item').length >= 2) break
  await wait(100)
}

const doc = window.document
const cases = [...doc.querySelectorAll('.case-item')]
check('案例卡片渲染', cases.length >= 2, `got ${cases.length}`)

const h1 = doc.querySelector('.case-header h1')
check('首个案例标题渲染', !!h1 && h1.textContent.includes('PHP2Shell'), h1?.textContent)

const stages = [...doc.querySelectorAll('.stage')]
check('S1–S7 流程时间线', stages.length === 7, `got ${stages.length}`)

const stageIds = stages.map((s) => s.querySelector('.stage-id').textContent)
check('阶段编号连续', JSON.stringify(stageIds) === JSON.stringify(['S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7']), stageIds.join(','))

const productRows = [...doc.querySelectorAll('.table-wrap tbody tr')]
check('产品矩阵表格有行', productRows.length >= 8, `got ${productRows.length}`)

const pills = [...doc.querySelectorAll('.pill')].map((p) => p.textContent)
check('命中/未命中状态徽章', pills.includes('打穿') && pills.includes('未命中'), pills.slice(0, 3).join(','))

const chips = [...doc.querySelectorAll('.chip b')].map((b) => b.textContent)
check('汇总统计块', chips.length >= 3, chips.join(','))

const limits = doc.querySelectorAll('.limits li')
check('能力边界列表', limits.length >= 3, `got ${limits.length}`)

// The panel is open from the start, so there must be no "enter demo" button.
check('不再有「进入演示实例」按钮', doc.querySelector('#demoFocus') === null)

const resizer = doc.querySelector('#demoResizer')
check('存在面板宽度拖拽条', !!resizer)
check('拖拽条可聚焦（键盘可调）', resizer?.getAttribute('tabindex') === '0')

// Panel width must be a CSS variable the resizer can drive.
const demoW = window.getComputedStyle(window.document.documentElement).getPropertyValue('--demo-w').trim()
check('面板宽度由变量驱动', /^\d+px$/.test(demoW), demoW)

const side = doc.querySelector('#demoSide')
check('演示面板在侧栏', !!side && !doc.querySelector('.content').contains(side))

const expBtn = doc.querySelector('#expBtn')
check('宿主机阶段有 exp 按钮', !!expBtn, expBtn?.textContent)

const hostNote = doc.querySelector('#hostNote')
check('明确标注不可手动输入', /不可手动输入/.test(hostNote?.textContent || ''))

const victimRow = doc.querySelector('#victimRow')
check('受害者输入框初始隐藏', victimRow?.hidden === true)

// `hidden` alone is not enough: a display rule can override it. Assert the
// resolved style so this regression cannot slip through again.
check('受害者输入框确实不可见', window.getComputedStyle(victimRow).display === 'none',
  window.getComputedStyle(victimRow).display)

const targetRows = [...doc.querySelectorAll('.target-row')]
check('靶场状态列表', targetRows.length >= 4, `got ${targetRows.length}`)

// Switch to the session-poison case by id (position is not stable) and
// confirm re-render works.
const poisonCard = cases.find((b) => b.dataset.id === 'session-poison')
check('可按 id 定位案例卡片', !!poisonCard)
poisonCard.dispatchEvent(new window.MouseEvent('click', { bubbles: true }))
await wait(300)
const h1b = doc.querySelector('.case-header h1')
check('切换案例后重渲染', !!h1b && h1b.textContent.includes('session.upload_progress'), h1b?.textContent)

const noCve = doc.querySelector('.badge.nocve')
check('无 CVE 案例显示正确徽章', !!noCve, noCve?.textContent)

const unevalPills = [...doc.querySelectorAll('.pill')].map((p) => p.textContent)
check('未能评估与未命中区分', unevalPills.includes('未能评估') && unevalPills.includes('未命中'))



console.log(failures === 0 ? '\nALL RENDER CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`)
process.exit(failures === 0 ? 0 : 1)
