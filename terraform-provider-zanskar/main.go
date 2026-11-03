// SPDX-License-Identifier: Apache-2.0

// Command terraform-provider-zanskar is the Terraform provider for Zanskar
// (ADR 0044). Terraform starts it; it is not run by hand.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/albatroxxx/zanskar/terraform-provider-zanskar/internal/provider"
)

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	debug := flag.Bool("debug", false, "run with support for debuggers such as delve")
	flag.Parse()
	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/albatroxxx/zanskar",
		Debug:   *debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
