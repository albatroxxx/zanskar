/** terminalTheme reads the always-dark terminal tokens from the stylesheet so
 *  xterm's canvas matches the page chrome around it. One source of truth for
 *  the colours lives in tokens.css; the fallbacks only matter before CSS loads. */
export function terminalTheme() {
  const s = getComputedStyle(document.documentElement)
  const v = (name: string, fallback: string) => s.getPropertyValue(name).trim() || fallback
  return {
    background: v('--terminal-bg', '#181a1f'),
    foreground: v('--term-fg', '#e8e4da'),
    cursor: v('--term-link', '#a9b4ff'),
    cursorAccent: v('--terminal-bg', '#181a1f'),
    selectionBackground: 'rgba(169, 180, 255, 0.28)',
  }
}
