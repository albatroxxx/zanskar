// Captures the site's console screenshots from a gateway seeded by seed.sh,
// through headless Chrome's DevTools protocol (no extra packages).
//
//   node hack/screenshots/shoot.mjs <cdp-port> <base-url> <admin-cookie> <alice-cookie> <out-dir> <version>
//
// Start Chrome first, e.g.:
//   "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new \
//     --remote-debugging-port=9333 --user-data-dir="$(mktemp -d)" about:blank
import fs from 'node:fs'
import path from 'node:path'

const [port, base, adminCookie, aliceCookie, outDir, version] = process.argv.slice(2)
if (!version) {
  console.error('usage: shoot.mjs <cdp-port> <base-url> <admin-cookie> <alice-cookie> <out-dir> <version>')
  process.exit(2)
}
const host = new URL(base).hostname

const tabs = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json()
const ws = new WebSocket(tabs.find((t) => t.type === 'page').webSocketDebuggerUrl)
await new Promise((r) => (ws.onopen = r))
let next = 0
const waiting = new Map()
ws.onmessage = (m) => {
  const d = JSON.parse(m.data)
  const resolve = waiting.get(d.id)
  if (typeof resolve === 'function') {
    waiting.delete(d.id)
    resolve(d)
  }
}
const send = (method, params = {}) =>
  new Promise((r) => {
    const id = ++next
    waiting.set(id, r)
    ws.send(JSON.stringify({ id, method, params }))
  })
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

await send('Network.enable')
await send('Emulation.setDeviceMetricsOverride', { width: 1568, height: 720, deviceScaleFactor: 1, mobile: false })
// The guide's shots are dark; the front page and the README take the
// dashboard in both schemes, so the light one sits flush on the site's paper.
const scheme = (value) => send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value }] })
await scheme('dark')

async function as(cookie) {
  await send('Network.clearBrowserCookies')
  await send('Network.setCookies', { cookies: [{ name: 'zanskar_session', value: cookie, domain: host, path: '/' }] })
}
// Every shot is taken in both schemes: the guide shows the dark set
// (`name-version.jpg`), the front page the light one (`name-light-version.jpg`).
async function shot(name, url, after, height = 720) {
  for (const value of ['dark', 'light']) {
    await scheme(value)
    await send('Emulation.setDeviceMetricsOverride', { width: 1568, height, deviceScaleFactor: 1, mobile: false })
    await send('Page.navigate', { url: base + url })
    await sleep(2000)
    if (after) {
      await send('Runtime.evaluate', { expression: after, awaitPromise: true })
      await sleep(800)
    }
    const { result } = await send('Page.captureScreenshot', { format: 'jpeg', quality: 85 })
    await save(value === 'dark' ? name : `${name}-light`, result.data)
  }
}
async function save(name, data) {
  const file = path.join(outDir, `${name}-${version}.jpg`)
  fs.writeFileSync(file, Buffer.from(data, 'base64'))
  console.log(file)
  // The README shows a few of these under names without a version, so a
  // release never means a README edit; refresh those copies when the
  // repository's directory for them is beside this script.
  const readmeDir = path.join(path.dirname(new URL(import.meta.url).pathname), '..', '..', 'docs', 'assets', 'screenshots')
  if (fs.existsSync(path.join(readmeDir, `${name}.jpg`))) fs.copyFileSync(file, path.join(readmeDir, `${name}.jpg`))
}

await as(adminCookie)
// The dashboard is taken taller, so the gateway card is whole.
await shot('dashboard', '/admin', undefined, 824)
await shot('hosts', '/admin/hosts')
await shot('databases', '/admin/databases')
await shot('applications', '/admin/applications')
await shot('policies', '/admin/policies')
await shot('approvals', '/admin/approvals')
// The certificate authority's Setup panel, opened from its row.
await shot('ssh-ca', '/admin/credentials',
  `[...document.querySelectorAll('tr')].find((r) => r.textContent.includes('linux-fleet-ca'))?.querySelector('button')?.click()`)
// The audit log, with the first access decision's details open.
await shot('audit-events', '/admin/events',
  `[...document.querySelectorAll('tr')].find((r) => r.textContent.includes('request for'))?.querySelector('details')?.setAttribute('open', '')`, 800)
// The command line, last: its commands are audit events of their own.
await shot('console-cli', '/admin/policies', `(async () => {
  const wait = (ms) => new Promise((r) => setTimeout(r, ms))
  document.querySelector('button[aria-label="Command line"]').click()
  await wait(500)
  for (const line of ['status', 'requests --pending']) {
    const input = document.querySelector('.cli-prompt input')
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, line)
    input.dispatchEvent(new Event('input', { bubbles: true }))
    input.form.requestSubmit()
    await wait(700)
  }
})()`, 800)
// The corner strip (ADR 0032): the gear's actions, and the bell's panel.
await shot('gateway-gear', '/admin', `document.querySelector('button[aria-label="Gateway actions"]').click()`)
await shot('updates-bell', '/admin', `document.querySelector('button[aria-label^="Zanskar"], button[aria-label="Updates"]').click()`)
await as(aliceCookie)
await shot('user-targets', '/')
// The Applications tab (ADR 0033): each opens in its own tab at its own address.
await shot('user-applications', '/', `[...document.querySelectorAll('[role="tab"]')].find((t) => t.textContent.startsWith('Applications'))?.click()`)
ws.close()
