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
const waiting = {}
ws.onmessage = (m) => {
  const d = JSON.parse(m.data)
  if (d.id && waiting[d.id]) {
    waiting[d.id](d)
    delete waiting[d.id]
  }
}
const send = (method, params = {}) =>
  new Promise((r) => {
    const id = ++next
    waiting[id] = r
    ws.send(JSON.stringify({ id, method, params }))
  })
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

await send('Network.enable')
await send('Emulation.setDeviceMetricsOverride', { width: 1568, height: 720, deviceScaleFactor: 1, mobile: false })
await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: 'dark' }] })

async function as(cookie) {
  await send('Network.clearBrowserCookies')
  await send('Network.setCookies', { cookies: [{ name: 'zanskar_session', value: cookie, domain: host, path: '/' }] })
}
async function shot(name, url, after, height = 720) {
  await send('Emulation.setDeviceMetricsOverride', { width: 1568, height, deviceScaleFactor: 1, mobile: false })
  await send('Page.navigate', { url: base + url })
  await sleep(2000)
  if (after) {
    await send('Runtime.evaluate', { expression: after })
    await sleep(800)
  }
  const { result } = await send('Page.captureScreenshot', { format: 'jpeg', quality: 85 })
  const file = path.join(outDir, `${name}-${version}.jpg`)
  fs.writeFileSync(file, Buffer.from(result.data, 'base64'))
  console.log(file)
}

await as(adminCookie)
await shot('hosts', '/admin')
await shot('databases', '/admin/databases')
await shot('policies', '/admin/policies')
await shot('approvals', '/admin/approvals')
// The certificate authority's Setup panel, opened from its row.
await shot('ssh-ca', '/admin/credentials',
  `[...document.querySelectorAll('tr')].find((r) => r.textContent.includes('linux-fleet-ca'))?.querySelector('button')?.click()`)
// The audit log, with the first access decision's details open.
await shot('audit-events', '/admin/events',
  `[...document.querySelectorAll('tr')].find((r) => r.textContent.includes('request for'))?.querySelector('details')?.setAttribute('open', '')`, 800)
await as(aliceCookie)
await shot('user-targets', '/')
ws.close()
