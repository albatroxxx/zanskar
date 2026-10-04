import { describe, expect, it } from 'vitest'
import { protocolName } from './format'

// Protocols read as names, not codes: acronyms stay acronyms, WinRM keeps its
// spelling, and "database" is a word (the console used to show DATABASE).
describe('protocolName', () => {
  it.each([
    ['ssh', 'SSH'],
    ['rdp', 'RDP'],
    ['vnc', 'VNC'],
    ['winrm', 'WinRM'],
    ['database', 'database'],
  ])('%s reads as %s', (code, want) => {
    expect(protocolName(code)).toBe(want)
  })
})
