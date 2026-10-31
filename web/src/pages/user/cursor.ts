// One cursor over a remote desktop (2026-11-01). The remote machine's pointer
// becomes the browser's own cursor over the desktop, its shape and hotspot as
// the remote draws them, the way Apache Guacamole's own client does it; the
// library's software cursor, a layer it moves after each mouse event and so a
// frame behind the real pointer, is only the fallback.

// The largest image Chromium and Firefox take as a CSS cursor; a bigger one is
// ignored and the default arrow shown in its place, the wrong shape.
export const MAX_CURSOR = 128

/** The part of Guacamole.Mouse this needs: it sets the element's CSS cursor
 *  to the canvas, reporting false when the browser has no image cursors. */
interface CursorMouse {
  setCursor(canvas: HTMLCanvasElement, x: number, y: number): boolean
}

/**
 * pointerAsCursor makes the remote pointer image the browser's cursor over
 * el, and reports whether it did. When it cannot (an image too big, an empty
 * one, a browser without image cursors) the element's own cursor is hidden
 * instead, so the software cursor the caller then shows is still the only
 * one. An empty image is the remote hiding its pointer: nothing shows.
 */
export function pointerAsCursor(mouse: CursorMouse, el: HTMLElement, canvas: HTMLCanvasElement, x: number, y: number): boolean {
  const fits = canvas.width > 0 && canvas.height > 0 && canvas.width <= MAX_CURSOR && canvas.height <= MAX_CURSOR
  if (fits && mouse.setCursor(canvas, x, y)) return true
  el.style.cursor = 'none'
  return false
}
