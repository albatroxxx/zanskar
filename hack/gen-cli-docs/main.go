// SPDX-License-Identifier: Apache-2.0

// Command gen-cli-docs prints the console command line's reference,
// docs/console-cli.md, from the command table in internal/cli.
//
//	go run ./hack/gen-cli-docs > docs/console-cli.md
package main

import (
	"fmt"

	"github.com/albatroxxx/zanskar/internal/cli"
)

func main() {
	fmt.Print(cli.Reference())
}
