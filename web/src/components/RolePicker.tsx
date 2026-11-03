import { useRef } from 'react'
import { normalizeRoles } from '../api/roles'
import type { Role } from '../api/types'

const order: Role[] = ['admin', 'auditor', 'user']

/**
 * RolePicker ticks an account's roles (2026-11-03: with admin ticked, the
 * auditor and user boxes still asked to be ticked too). Admin includes the
 * other two, so ticking it shows them ticked and greyed out, with a word on
 * why; unticking it gives back what was chosen before it. What it hands
 * onChange is always as the gateway keeps it.
 */
export function RolePicker({ value, onChange, idPrefix }: { value: Role[]; onChange: (roles: Role[]) => void; idPrefix: string }) {
  const admin = value.includes('admin')
  // What was chosen before admin was ticked, to give back when it is not.
  const before = useRef<Role[]>(admin ? [] : value)
  const toggle = (r: Role, on: boolean) => {
    if (r === 'admin') {
      if (on) {
        before.current = value.filter((x) => x !== 'admin')
        onChange(['admin'])
      } else {
        onChange(normalizeRoles(before.current))
      }
      return
    }
    onChange(normalizeRoles(on ? [...value, r] : value.filter((x) => x !== r)))
  }
  const note = `${idPrefix}-role-note`
  return (
    <div>
      <div className="actions">
        {order.map((r) => {
          const included = admin && r !== 'admin'
          const id = `${idPrefix}-role-${r}`
          return (
            <span key={r} className="field inline role-check">
              <input
                id={id}
                type="checkbox"
                checked={included || value.includes(r)}
                disabled={included}
                aria-describedby={included ? note : undefined}
                onChange={(e) => toggle(r, e.target.checked)}
              />
              <label htmlFor={id}>{r}</label>
            </span>
          )
        })}
      </div>
      {admin && <span className="hint" id={note}>Admin includes auditor and user.</span>}
    </div>
  )
}
