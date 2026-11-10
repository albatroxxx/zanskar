// SPDX-License-Identifier: Apache-2.0

// Command gen-lifecycles prints docs/lifecycles.md from the lifecycles the
// code declares (ADR 0047).
//
//	go run ./hack/gen-lifecycles > docs/lifecycles.md
package main

import (
	"fmt"

	"github.com/albatroxxx/zanskar/internal/states/catalog"
)

func main() {
	fmt.Print(catalog.Document())
}
