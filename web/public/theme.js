// Applies the console theme chosen in the corner menu before the first
// paint, so a page never flashes the other theme while it loads. A file, not
// an inline script: the console's CSP allows scripts from its own origin
// only. "system" (no data-theme) follows the operating system.
;(function () {
  try {
    var t = localStorage.getItem('zanskar.theme')
    if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t)
  } catch (e) {
    // Storage blocked: the operating system's theme applies.
  }
})()
