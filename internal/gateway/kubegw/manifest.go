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
	account := "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: " + ServiceAccount + "\n  namespace: kube-system\n---\n"
	subject := "  - kind: ServiceAccount\n    name: " + ServiceAccount + "\n    namespace: kube-system\n"
	trailer := "---\n# Token for the kube_token credential:\n#   kubectl -n kube-system create token " + ServiceAccount + " --duration=8760h\n"
	return manifest(groups, account, subject, trailer)
}

// ManifestEKS is the same RBAC for an EKS cluster reached through a role
// (ADR 0045, 8): no ServiceAccount, since the cluster maps the role to a
// user by its access entry or aws-auth line, which the binding names.
// mapping is that step, printed for the administrator who has not done it.
func ManifestEKS(groups []string, user, mapping string) string {
	subject := "  - kind: User\n    name: " + user + "\n    apiGroup: rbac.authorization.k8s.io\n"
	trailer := "---\n# The cluster maps Zanskar's role to the user " + user + ":\n"
	for _, l := range strings.Split(mapping, "\n") {
		trailer += "#   " + l + "\n"
	}
	return manifest(groups, "", subject, trailer)
}

func manifest(groups []string, account, subject, trailer string) string {
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
	b.WriteString(account)
	b.WriteString("apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: zanskar-impersonator\nrules:\n")
	b.WriteString("  - apiGroups: [\"\"]\n    resources: [\"users\"]\n    verbs: [\"impersonate\"]\n")
	b.WriteString("  - apiGroups: [\"\"]\n    resources: [\"groups\"]\n    verbs: [\"impersonate\"]\n    resourceNames:\n")
	for _, g := range ok {
		fmt.Fprintf(&b, "      - %q\n", g)
	}
	b.WriteString("---\napiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: zanskar-impersonator\n")
	b.WriteString("roleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n  name: zanskar-impersonator\n")
	b.WriteString("subjects:\n" + subject)
	b.WriteString(trailer)
	return b.String()
}
