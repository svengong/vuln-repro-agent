// Verify the demo panel can be resized by dragging, is clamped, and remembers
// its width across reloads.
import { JSDOM } from '/home/sven/workspace/dsh-codebuddy-connect/node_modules/jsdom/lib/api.js'
import { readFile } from 'node:fs/promises'

const BASE = 'http://127.0.0.1:3010'
const WEB = '/home/sven/workspace/vuln-dashboard/web'

const html = await readFile(WEB + '/index.html', 'utf8')
const appSrc = await readFile(WEB + '/app.js', 'utf8')

let fail = 0
const check = (n, c, d = '') => {
  if (c) console.log('  PASS  ' + n)
  else { console.log('  FAIL  ' + n + (d ? ' — ' + d : '')); fail++ }
}
const wait = (ms) => new Promise((r) => setTimeout(r, ms))

// jsdom reports 1024x768 by default; give it a realistic desktop viewport so
// the clamp maths has room to work.
const SHARED_STORE = new Map()

async function boot (width = 1600, store = SHARED_STORE) {

  const dom = new JSDOM(html, {
    url: BASE + '/',
    runScripts: 'outside-only',
    pretendToBeVisual: true,
    beforeParse (window) {
      Object.defineProperty(window, 'innerWidth', { writable: true, value: width })
      window.localStorage.__store = store
    }
  })
  const { window } = dom
  window.fetch = (i, init) => fetch(new URL(i, BASE), init)
  window.TextDecoder = TextDecoder
  // Simple deterministic localStorage stand-in shared across "reloads".
  Object.defineProperty(window, 'localStorage', {
    value: {
      getItem: (k) => (store.has(k) ? store.get(k) : null),
      setItem: (k, v) => store.set(k, String(v)),
      removeItem: (k) => store.delete(k)
    }
  })
  // jsdom lacks pointer capture on some elements.
  window.Element.prototype.setPointerCapture = function () {}
  window.Element.prototype.releasePointerCapture = function () {}
  window.eval(appSrc)
  await wait(500)
  return { window, doc: window.document, store }
}

const panelWidth = (window) =>
  parseFloat(window.getComputedStyle(window.document.documentElement).getPropertyValue('--demo-w')) || 0

// ---- default ----
const { window, doc } = await boot()
check('默认宽度 460px', panelWidth(window) === 460, String(panelWidth(window)))

const bar = doc.querySelector('#demoResizer')
check('拖拽条存在', !!bar)

// ---- drag to widen: pointer x moves left => panel grows ----
const drag = (targetX) => {
  bar.dispatchEvent(new window.MouseEvent('pointerdown', { bubbles: true, clientX: 1000, pointerId: 1 }))
  window.dispatchEvent(new window.MouseEvent('pointermove', { bubbles: true, clientX: targetX, pointerId: 1 }))
  window.dispatchEvent(new window.MouseEvent('pointerup', { bubbles: true, clientX: targetX, pointerId: 1 }))
}

drag(1000) // innerWidth 1600 - 1000 = 600
await wait(60)
check('拖拽后变宽到 600px', panelWidth(window) === 600, String(panelWidth(window)))

// ---- drag beyond max is clamped ----
drag(100) // would be 1500
await wait(60)
const capped = panelWidth(window)
check('超宽被钳制（≤900）', capped <= 900 && capped >= 320, String(capped))

// ---- drag beyond min is clamped ----
drag(1599) // would be 1
await wait(60)
check('超窄被钳制（≥320）', panelWidth(window) >= 320, String(panelWidth(window)))

// ---- double-click resets ----
drag(1000)
await wait(60)
bar.dispatchEvent(new window.MouseEvent('dblclick', { bubbles: true }))
await wait(60)
check('双击复位为 460px', panelWidth(window) === 460, String(panelWidth(window)))

// ---- width persists across reload ----
drag(1100) // 1600-1100 = 500
await wait(60)
const saved = panelWidth(window)
check('调整后宽度为 500px', saved === 500, String(saved))

const { window: w2 } = await boot()
check('重新加载后记住宽度', panelWidth(w2) === 500, String(panelWidth(w2)))

// ---- keyboard nudge ----
const { window: w3, doc: d3 } = await boot()
const bar3 = d3.querySelector('#demoResizer')
const before = panelWidth(w3)
bar3.dispatchEvent(new w3.KeyboardEvent('keydown', { key: 'ArrowLeft', bubbles: true }))
await wait(60)
check('键盘 ← 加宽', panelWidth(w3) === before + 24, `${before} -> ${panelWidth(w3)}`)

console.log(fail === 0 ? '\nALL RESIZE CHECKS PASSED' : `\n${fail} CHECK(S) FAILED`)
process.exit(fail === 0 ? 0 : 1)
