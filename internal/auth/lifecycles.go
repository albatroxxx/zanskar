// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/states"
)

// SignInLifecycle is the sign-in's declared lifecycle (ADR 0047): which step
// is owed next. No column holds it; it is derived from the account (an
// authenticator enrolled, a password change owed), the runtime setting that
// requires a second factor, and the session's mfa_verified. The login
// response's `status` and `/auth/me`'s `pending` are its words on the wire.
var SignInLifecycle = states.New("sign-in",
	[]string{"password", "verify", "enroll", "change", "signed in"},
	states.Move{From: "password", To: "signed in", By: audit.UserLogin + " (no authenticator, none required, no change owed): ok"},
	states.Move{From: "password", To: "verify", By: audit.UserLogin + " with an authenticator enrolled: mfa_required"},
	states.Move{From: "password", To: "enroll", By: audit.UserLogin + " with one required and none enrolled: mfa_enrollment_required"},
	states.Move{From: "password", To: "change", By: audit.UserLogin + " with a change owed and no authenticator: password_change_required"},
	states.Move{From: "verify", To: "signed in", By: audit.UserMFAVerify},
	states.Move{From: "verify", To: "change", By: audit.UserMFAVerify + " with a change owed: /auth/me says pending password"},
	states.Move{From: "enroll", To: "signed in", By: audit.UserMFAConfirm},
	states.Move{From: "change", To: "signed in", By: audit.UserPasswordChange},
	states.Move{From: "change", To: "verify", By: audit.UserPasswordChange + " with an authenticator enrolled"},
	states.Move{From: "change", To: "enroll", By: audit.UserPasswordChange + " with one required and none enrolled"},
	states.Move{From: "verify", To: "password", By: "too many wrong codes, or the partial session lapsed (sign_in_ended)"},
	states.Move{From: "enroll", To: "password", By: "too many wrong codes, or the partial session lapsed"},
).Describe(states.Doc{
	Derivation: "`LoginResponse.status` after the password or the change; `Me.pending` (`verify`, `enroll`, `password`) for a partial session that is read again; " +
		"single sign-on enters at `signed in`, or at `verify` or `enroll` when the provider leaves the second factor to Zanskar.",
	Notes: []string{
		"The console's own step follows the gateway's word after every answer (2026-11-09: it stayed on the code form after a right code when a password change was owed).",
		"A partial session may call only the sign-in routes, `/auth/me` and `/auth/logout`.",
	},
})

// SessionLifecycle is the sign-in session's (auth_sessions) declared
// lifecycle. Lookup derives usability from the row on every request.
var SessionLifecycle = states.New("sign-in session",
	[]string{"partial", "full", "expired", "revoked", "swept"},
	states.Move{From: "partial", To: "full", By: "the owed step is done (mfa_verified set)"},
	states.Move{From: "partial", To: "revoked", By: "too many wrong codes; the account is locked; sign-out"},
	states.Move{From: "partial", To: "expired", By: "the absolute or idle limit passes"},
	states.Move{From: "full", To: "expired", By: "12 h since sign-in, or 60 min idle"},
	states.Move{From: "full", To: "revoked", By: audit.UserLogout + ", a sign-in that replaces it, " + audit.UserSessionsRevoke + ", a password reset or change, an authenticator reset, the account disabled or deleted"},
	states.Move{From: "expired", To: "swept", By: "the hourly sweep, 24 h after the absolute expiry"},
	states.Move{From: "revoked", To: "swept", By: "the hourly sweep"},
).Describe(states.Doc{
	Derivation: "Usable while `revoked_at` is null, `expires_at` is ahead and `last_seen_at` is within the idle limit; `mfa_verified` tells partial from full. " +
		"Idle expiry is known only to Lookup: nothing selects it, so an idle-ended row stays until the sweep.",
	Notes: []string{
		"`mfa_verified_at` is the proof a code was typed or a security key touched; three windows read it (5 min for step-up, 15 min with a slide for the command line, 5 min from sign-in to enrol without a password).",
		"A disabled account's session is not revoked by the check that notices it; each status writer revokes.",
	},
})

// AuthenticatorLifecycle is the account's authenticator app (mfa_totp).
// Security keys (ADR 0028) are plain rows beside it with no lifecycle.
var AuthenticatorLifecycle = states.New("authenticator",
	[]string{"none", "enrolling", "confirmed"},
	states.Move{From: "none", To: "enrolling", By: audit.UserMFAEnroll},
	states.Move{From: "enrolling", To: "enrolling", By: audit.UserMFAEnroll + " again: a fresh secret"},
	states.Move{From: "enrolling", To: "confirmed", By: audit.UserMFAConfirm + " (eight recovery codes made when the account has no key)"},
	states.Move{From: "confirmed", To: "none", By: audit.UserMFAReset},
	states.Move{From: "enrolling", To: "none", By: audit.UserMFAReset},
).Describe(states.Doc{
	Derivation: "No row is `none`; a row with `confirmed_at` null is `enrolling`; `confirmed_at` set is `confirmed`.",
	Notes: []string{
		"Security keys (ADR 0028) count beside the app: an account has a second factor when its app is `confirmed` or it has at least one key (`Me.mfa_enrolled`, `Me.second_factor`). A key is a plain row in `webauthn_credentials`, registered and removed, with no states of its own.",
		"Recovery codes come with an account's first second factor of any kind; they have no count on the wire, and their use is an audit detail.",
		"\"Enrolled\" is read three ways: `Factors.Enrolled` (sign-in, tokens, approvals, the command line), the provider-aware rule over it (the connect gate), and the posture SQL (the dashboard).",
	},
})
