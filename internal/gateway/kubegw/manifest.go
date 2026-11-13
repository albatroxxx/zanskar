// SPDX-License-Identifier: Apache-2.0

package kubegw

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// GroupPrefix is what a person's Zanskar group reads as in the cluster:
// zanskar:<group name>, sent as Impersonate-Group so the cluster's RBAC can
// bind roles to it (ADR 0045, 2).
const GroupPrefix = "zanskar:"

// ServiceAccount is what the printed manifest names Zanskar's account; the
// administrator may bind an existing one instead.
const ServiceAccount = "zanskar"

var groupNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// ValidGroupName reports whether a Zanskar group's name can be an RBAC
// resource name, so the manifest binds it and a session may act as it.
func ValidGroupName(name string) bool { return groupNameRe.MatchString(name) }

// Manifest is the RBAC the cluster needs and nothing else (ADR 0009,
// agentless): a ClusterRole that may impersonate users and the groups
// Zanskar knows, a ServiceAccount to hold Zanskar's credential and the
// binding between them. groups are the Zanskar group names the clusters'
// policies name; the administrator binds their own roles to
// zanskar:<group>. A group whose name cannot be an RBAC resourceName is
// left out and named in the comment.
func Manifest(groups []string) string {
	var ok, skipped []string
	for _, g := range groups {
		if groupNameRe.MatchString(g) {
			ok = append(ok, GroupPrefix+g)
		} else {
			skipped = append(skipped, g)
		}
	}
	sort.Strings(ok)
	ok = append([]string{"system:authenticated"}, ok...)
	var b strings.Builder
	// What an operator pastes carries what the YAML cannot say for itself,
	// and no more: whose it is, and the one thing left out.
	b.WriteString("# Zanskar: impersonation only. Bind your roles to the groups zanskar:<group>.\n")
	if len(skipped) > 0 {
		fmt.Fprintf(&b, "# Not listed (not valid RBAC names): %s\n", strings.Join(skipped, ", "))
	}
	b.WriteString("apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: " + ServiceAccount + "\n  namespace: kube-system\n---\n")
	b.WriteString("apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: zanskar-impersonator\nrules:\n")
	b.WriteString("  - apiGroups: [\"\"]\n    resources: [\"users\"]\n    verbs: [\"impersonate\"]\n")
	b.WriteString("  - apiGroups: [\"\"]\n    resources: [\"groups\"]\n    verbs: [\"impersonate\"]\n    resourceNames:\n")
	for _, g := range ok {
		fmt.Fprintf(&b, "      - %q\n", g)
	}
	b.WriteString("---\napiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: zanskar-impersonator\n")
	b.WriteString("roleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n  name: zanskar-impersonator\n")
	b.WriteString("subjects:\n  - kind: ServiceAccount\n    name: " + ServiceAccount + "\n    namespace: kube-system\n")
	b.WriteString("---\n# Token for the kube_token credential:\n")
	b.WriteString("#   kubectl -n kube-system create token " + ServiceAccount + " --duration=8760h\n")
	return b.String()
}
