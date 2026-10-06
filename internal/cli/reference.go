// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"strings"
)

// Reference renders docs/console-cli.md from the command table, so the
// reference cannot drift from what the gateway accepts. Regenerate it with
// `go run ./hack/gen-cli-docs > docs/console-cli.md`; a test fails until you do.
func Reference() string {
	var b strings.Builder
	b.WriteString(`# The console command line

<!-- Generated from internal/cli by hack/gen-cli-docs. Do not edit by hand. -->

Administrators can work from a command line inside the console: the terminal-window icon at the
top right of every administrator page, or Ctrl+` + "`" + `, opens it at the bottom of the page. It
runs Zanskar commands only. It is not a shell, and it cannot reach the gateway's host
([ADR 0027](adr/0027-restricted-console-cli.md)).

## How it works

- **A fresh code opens it.** The first time you open it, and again after 15 minutes without a
  command, it asks for a code from your authenticator app (a recovery code also works). You
  need an authenticator enrolled; an account that signs in only through an identity provider
  cannot open it. Five wrong codes close it for 15 minutes; your sign-in is not affected.
- **It does what the console does, no more.** Each command makes the same API request the
  console would, through the same permission checks. Anything the console would refuse you,
  the command line refuses too.
- **Changes ask first.** Commands that end, remove or restart something say what will happen
  and ask you to type a word, usually the name of what you are changing. Anything else
  cancels.
- **Every line is recorded.** Each line you run, including the ones that only read, is an
  audit event (` + "`cli.command`" + `) with its result and the routes it called. A change also
  has its usual event just before it.
- **Not a shell.** Pipes, redirection, variables and command substitution are refused, and so
  is anything not in the list below. Host operations (backup, restore, key rotation, audit
  repair) are not commands: they need the host on purpose.
- **No secrets.** No command takes a password, key or token; setting those stays in the
  console's forms.
- **Turning it off.** Set ` + "`ZANSKAR_CONSOLE_CLI=off`" + ` in the environment file and restart.
  It is not a console setting, so a stolen sign-in cannot turn it back on.

Names work wherever there is one (users, targets, policies, autoscaling groups); ids work too. Sessions and
access requests are named by the first 8 characters of their id, as the lists show them; 6 are
enough when they are unique. Words with spaces go in quotes: ` + "`setting set login_banner \"Use is monitored\"`" + `.

The console also understands ` + "`clear`" + ` and ` + "`history`" + `, and the up and down arrows recall earlier
lines.

`)
	group := ""
	for _, c := range commands() {
		if c.group != group {
			group = c.group
			fmt.Fprintf(&b, "## %s\n\n", group)
		}
		fmt.Fprintf(&b, "### `%s`\n\n%s", c.usage(), c.summary)
		if c.plan != nil {
			b.WriteString(" Asks you to confirm first.")
		}
		b.WriteString("\n\n")
		if len(c.flags) > 0 {
			for _, f := range c.flags {
				name := "--" + f.name
				if f.value != "" {
					name += " " + f.value
				}
				fmt.Fprintf(&b, "- `%s`: %s\n", name, f.help)
			}
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "```\nzanskar> %s\n```\n\n", c.example)
	}
	return strings.TrimRight(b.String(), "\n") + "\n"
}
