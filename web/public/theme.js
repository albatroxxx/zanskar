// Applies the console theme before the first paint, so a page never flashes
// the other theme while it loads. A file, not an inline script: the console's
// CSP allows scripts from its own origin only. The gateway serves it with the
// theme an administrator set for everyone written over the literal marked
// zanskar:theme (display.theme); this browser's own pick from the corner
// switch comes first. "system" (no data-theme) follows the operating system.
;(function () {
  var root = document.documentElement
  var consoleTheme = 'system' /* zanskar:theme */
  root.setAttribute('data-theme-default', consoleTheme)
  var t = null
  try {
    t = localStorage.getItem('zanskar.theme')
  } catch {
    // Storage blocked: the console's theme applies.
  }
  if (t !== 'light' && t !== 'dark') t = consoleTheme
  if (t === 'light' || t === 'dark') root.setAttribute('data-theme', t)
})()
