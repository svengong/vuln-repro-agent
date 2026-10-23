// Verify the two-phase demo panel against the live server.
//
// Asserts the flow the product promises:
//   connect -> host pseudo-shell (no manual input, exp button only)
//           -> exp succeeds -> victim shell (manual input works)
import { JSDOM } from '/home/sven/workspace/dsh-codebuddy-connect/node_modules/jsdom/lib/api.js'
import { readFile } from 'node:fs/promises'

const BASE = 'http://127.0.0.1:3010'
const WEB = '/home/sven/workspace/vuln-dashboard/web'

const dom = new JSDOM(await readFile(WEB + '/index.html', 'utf8'),
  { url: BASE + '/', runScripts: 'outside-only', pretendToBeVisual: true })
const { window } = dom
window.fetch = (i, init) => fetch(new URL(i, BASE), init)
window.TextDecoder = TextDecoder
window.eval(await readFile(WEB + '/app.js', 'utf8'))

const wait = (ms) => new Promise((r) => setTimeout(r, ms))
const doc = window.document
let fail = 0
const check = (n, c, d = '') => {
  if (c) console.log('  PASS  ' + n)
  else { console.log('  FAIL  ' + n + (d ? ' — ' + d : '')); fail++ }
}
const until = async (fn, tries = 200) => {
  for (let i = 0; i < tries; i++) { if (fn()) return true; await wait(100) }
  return false
}

// ---- load & pick the session-poison case (fast webshell backend) ----
await until(() => doc.querySelectorAll('.case-item').length >= 2, 60)
check('案例列表加载', doc.querySelectorAll('.case-item').length >= 2)

// Pick by id: the number and order of cases changes as new ones are added.
const poisonCard = [...doc.querySelectorAll('.case-item')].find((b) => b.dataset.id === 'session-poison')
check('定位 session-poison 案例', !!poisonCard)
poisonCard.dispatchEvent(new window.MouseEvent('click', { bubbles: true }))
await wait(700)

// ---- layout: demo panel is a SIDE panel, not in the reading column ----
const side = doc.querySelector('#demoSide')
check('演示面板位于侧栏', !!side && side.closest('.layout') !== null)
const content = doc.querySelector('.content')
check('演示面板不在正文列内', !content.contains(side))
// The panel is open from the start, so there is no "enter demo" button.
check('不再有「进入演示实例」按钮', doc.querySelector('#demoFocus') === null)
check('面板默认即为展开的宿主机阶段',
  doc.querySelector('#hostRow').hidden === false && doc.querySelector('#demoSide').hidden === false)

// ---- phase 1: host pseudo-shell on connect ----
check('进入宿主机阶段', doc.querySelector('#hostRow').hidden === false)
check('受害者输入框初始隐藏', doc.querySelector('#victimRow').hidden === true)
const expBtn = doc.querySelector('#expBtn')
check('exp 按钮可用（未自动执行）', expBtn.disabled === false && /执行 exp/.test(expBtn.textContent), expBtn.textContent)
const termText0 = doc.querySelector('#termOut').textContent
check('连接后未自动执行 exp', !/uid=33/.test(termText0))
check('宿主机阶段提示不可手动输入', /不可手动输入/.test(doc.querySelector('#hostNote').textContent))

// ---- phase 2: click exp -> victim shell ----
expBtn.dispatchEvent(new window.MouseEvent('click', { bubbles: true }))
const reachedVictim = await until(() => doc.querySelector('#victimRow').hidden === false, 400)
const termText = doc.querySelector('#termOut').textContent
check('exp 执行后可进入受害者 shell', reachedVictim, termText.slice(-160))
check('exp 输出含打穿证据', /uid=33|www-data|PWNED/.test(termText))
check('受害者 shell 提示已解锁', /受害者 shell/.test(termText))

// ---- victim shell accepts manual commands ----
const input = doc.querySelector('#termInput')
input.value = 'id; pwd'
input.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Enter', bubbles: true }))
// Wait for the echoed prompt, not just any output — the exp log already
// contains /var/www/html, so a loose match would pass before the command ran.
await until(() => /victim\$ id; pwd/.test(doc.querySelector('#termOut').textContent), 200)
await until(() => /\[\d+ ms\]/.test(doc.querySelector('#termOut').textContent), 200)
const out = doc.querySelector('#termOut').textContent
const afterCmd = out.slice(out.lastIndexOf('victim$ id; pwd'))
check('受害者 shell 手动执行命令', /uid=33\(www-data\)/.test(afterCmd))
check('命令回显 pwd', /\/var\/www\/html/.test(afterCmd))

// ---- reset returns to host phase ----
doc.querySelector('#demoReset').dispatchEvent(new window.MouseEvent('click', { bubbles: true }))
await until(() => doc.querySelector('#hostRow').hidden === false, 100)
check('重置回到宿主机阶段', doc.querySelector('#hostRow').hidden === false)
check('重置后受害者输入框隐藏', doc.querySelector('#victimRow').hidden === true)

console.log(fail === 0 ? '\nALL DEMO-FLOW CHECKS PASSED' : `\n${fail} CHECK(S) FAILED`)
process.exit(fail === 0 ? 0 : 1)
