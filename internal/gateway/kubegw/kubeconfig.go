// SPDX-License-Identifier: Apache-2.0

package kubegw

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

// KubeconfigOptions is what a session's kubeconfig says.
type KubeconfigOptions struct {
	// Name is the cluster's name as enrolled; it names the context.
	Name string
	// Server is the gateway's endpoint for the session,
	// https://<public url>/k8s/<session id>.
	Server string
	// Token is the session token.
	Token string
	// CAPEM is the gateway's own certificate, when kubectl must be told to
	// trust it (a self-signed one); empty behind a certificate a client
	// trusts already, or a proxy that terminates TLS.
	CAPEM string
}

var nameRe = regexp.MustCompile(`[^a-z0-9-]+`)

// Kubeconfig is the file the person's tools read (ADR 0045, 3): one cluster,
// one user, one context, current. The token is the session's; the server is
// the gateway.
func Kubeconfig(o KubeconfigOptions) string {
	name := strings.Trim(nameRe.ReplaceAllString(strings.ToLower(o.Name), "-"), "-")
	if name == "" {
		name = "cluster"
	}
	name = "zanskar-" + name
	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: v1\nkind: Config\nclusters:\n- name: %s\n  cluster:\n    server: %s\n", name, o.Server)
	if o.CAPEM != "" {
		fmt.Fprintf(&b, "    certificate-authority-data: %s\n", base64.StdEncoding.EncodeToString([]byte(o.CAPEM)))
	}
	fmt.Fprintf(&b, "users:\n- name: %s\n  user:\n    token: %s\n", name, o.Token)
	fmt.Fprintf(&b, "contexts:\n- name: %s\n  context:\n    cluster: %s\n    user: %s\ncurrent-context: %s\n", name, name, name, name)
	return b.String()
}
