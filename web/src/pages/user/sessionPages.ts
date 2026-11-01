// The session pages' code, loaded on demand. The routes load it when they
// render; the connect page asks for it while its connect call is out, so the
// page is ready when the call answers (2026-11-01).

import type { Protocol } from '../../api/types'

export const loadTerminal = () => import('./Terminal').then((m) => ({ default: m.Terminal }))
export const loadDesktop = () => import('./Desktop').then((m) => ({ default: m.Desktop }))

/** The protocols whose session is a desktop (/ws/desktop): RDP, VNC, and an
 *  application's isolated browser. The rest are terminals. */
const desktops: Protocol[] = ['rdp', 'vnc', 'http']

/** preloadSessionPage fetches the code of the page a session over protocol
 *  opens in. A failure is left to the route, which loads it again. */
export function preloadSessionPage(protocol: Protocol) {
  void (desktops.includes(protocol) ? loadDesktop() : loadTerminal()).catch(() => {})
}
