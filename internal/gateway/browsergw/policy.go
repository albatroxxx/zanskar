// SPDX-License-Identifier: Apache-2.0

package browsergw

import (
	"encoding/json"
	"net"
	"net/url"
	"strconv"
)

// socksPort is where the relay listens for the browser: 1080, or 1081 when
// the upstream's own forward already holds 1080 on the relay.
func socksPort(spec Spec) int {
	if upstreamPort(spec.Upstream) == 1080 {
		return 1081
	}
	return 1080
}

// proxyPort is where the relay's proxy that inspects listens: 3128, or
// 3129 when the upstream's own forward already holds 3128.
func proxyPort(spec Spec) int {
	if upstreamPort(spec.Upstream) == 3128 {
		return 3129
	}
	return 3128
}

// origin is an origin as the browser writes it, scheme://host[:port].
func origin(u *url.URL) string { return u.Scheme + "://" + u.Host }

// allowEntry is a URLAllowlist filter for exactly one origin: the scheme, the
// host and the port, every path. A name is written with a leading dot, which
// Chromium's filter reads as "this host, not its subdomains"; an IP literal
// has no subdomains and is written as it is. The relay refuses anything
// else whatever the filter says; the filter is what makes the browser show
// its own "blocked" page rather than a failed connection.
func allowEntry(u *url.URL) string {
	host, port := u.Hostname(), strconv.Itoa(upstreamPort(u))
	if ip := net.ParseIP(host); ip != nil {
		return u.Scheme + "://" + net.JoinHostPort(host, port)
	}
	return u.Scheme + "://." + host + ":" + port
}

// bookmark is one entry of Chromium's ManagedBookmarks policy.
type bookmark struct {
	Name         string `json:"name,omitempty"`
	URL          string `json:"url,omitempty"`
	TopLevelName string `json:"toplevel_name,omitempty"`
}

// policyJSON is the session browser's whole Chromium policy (ADR 0034, ADR
// 0037 and its amendment of 2026-11-02): the application's origins and
// nothing else, reached through the relay's SOCKS proxy, the upstream as the
// start page, the home page and every new tab, and, when the application has
// more origins than its upstream, all of them as one bookmarks folder named
// after it. Chromium's internal pages, files, javascript: and view-source:
// are blocked by name beside the blanket rule; so are downloads, printing,
// extensions, sign-in, sync, saved passwords, autofill, safe browsing,
// metrics, translation, prediction (which would open connections to pages
// nobody asked for) and WebRTC over anything but the proxy. Developer tools
// open only when the session's grant allows them.
func policyJSON(spec Spec, relayIP string) (string, error) {
	home := origin(spec.Upstream) + "/"
	// Under public dependencies (ADR 0037, amended 2026-11-03, later) the
	// relay's proxy reads every request and keeps a page to the origins
	// itself, and Chromium's catch-all goes: it blocked frames too, which
	// are dependencies. Held to its origins, the catch-all and the
	// allowlist keep the browser to them before anything leaves it.
	var allow, block []string
	proxy := "socks5://" + net.JoinHostPort(relayIP, strconv.Itoa(socksPort(spec)))
	if spec.PublicDependencies {
		// The proxy's own address is plain: it is on the session's private
		// network, two containers with no route out, and what goes through
		// it is TLS end to end with the relay (CONNECT).
		proxy = "http://" + net.JoinHostPort(relayIP, strconv.Itoa(proxyPort(spec))) // NOSONAR
	} else {
		allow = []string{allowEntry(spec.Upstream)}
		for _, e := range spec.Endpoints {
			allow = append(allow, allowEntry(e.URL))
		}
		block = []string{"*"}
	}
	block = append(block, "chrome://*", "chrome-untrusted://*", "file://*", "javascript:*", "view-source:*")
	devtools := 2
	if spec.DevTools {
		devtools = 1
		allow = append(allow, "devtools://*")
	} else {
		block = append(block, "devtools://*")
	}
	p := map[string]any{
		// Every scheme goes to the relay, loopback included ("<-loopback>"
		// takes away Chromium's implicit bypass), so nothing in the
		// container, the VNC server least of all, is a page's to reach.
		"ProxySettings": map[string]any{
			"ProxyMode":       "fixed_servers",
			"ProxyServer":     proxy,
			"ProxyBypassList": "<-loopback>",
		},
		"URLBlocklist":              block,
		"DownloadRestrictions":      3,
		"AllowFileSelectionDialogs": false, "PromptForDownloadLocation": false,
		"DeveloperToolsAvailability": devtools,
		"ExtensionInstallBlocklist":  []string{"*"},
		"PrintingEnabled":            false,
		"BrowserSignin":              0, "SyncDisabled": true, "PasswordManagerEnabled": false,
		"AutofillAddressEnabled": false, "AutofillCreditCardEnabled": false,
		"SafeBrowsingEnabled": false, "MetricsReportingEnabled": false, "TranslateEnabled": false,
		"DnsOverHttpsMode": "off", "BackgroundModeEnabled": false,
		"NetworkPredictionOptions": 2, "WebRtcIPHandlingPolicy": "disable_non_proxied_udp",
		// No search from the address bar: with dependencies let out to
		// public addresses (2026-11-03), what a person types would
		// otherwise go to the search engine as suggestions, keystroke by
		// keystroke (seen at the relay: duckduckgo.com), and a search is a
		// page the policy blocks anyway.
		"DefaultSearchProviderEnabled": false, "SearchSuggestEnabled": false,
		"AudioCaptureAllowed": false, "VideoCaptureAllowed": false, "ScreenCaptureAllowed": false,
		"DefaultGeolocationSetting": 2, "DefaultNotificationsSetting": 2,
		"IncognitoModeAvailability": 1, "BrowserGuestModeEnabled": false, "BrowserAddPersonEnabled": false,
		"HomepageLocation": home, "HomepageIsNewTabPage": false, "ShowHomeButton": true,
		"NewTabPageLocation": home, "RestoreOnStartup": 4, "RestoreOnStartupURLs": []string{home},
		"BookmarkBarEnabled": len(spec.Endpoints) > 0, "DefaultBrowserSettingEnabled": false, "BrowserLabsEnabled": false,
		"PromotionalTabsEnabled": false, "ShoppingListEnabled": false,
		// The command line carries the resolver rules; the bar warning
		// about them would show the session's internal addressing.
		"CommandLineFlagSecurityWarningsEnabled": false,
	}
	// No allowlist at all rather than an empty one: Chromium reads an empty
	// list as a policy set to nothing.
	if len(allow) > 0 {
		p["URLAllowlist"] = allow
	}
	if len(spec.Endpoints) > 0 {
		name := spec.Name
		if name == "" {
			name = spec.Upstream.Host
		}
		marks := []bookmark{{TopLevelName: name}, {Name: name, URL: home}}
		for _, e := range spec.Endpoints {
			marks = append(marks, bookmark{Name: e.Name, URL: origin(e.URL) + "/"})
		}
		p["ManagedBookmarks"] = marks
	}
	b, err := json.Marshal(p)
	return string(b), err
}

// resolverRules maps the upstream's name to the relay for a browser image
// from before the proxy, keeps the relay's own address, which the proxy
// setting names, from the rule after it, and maps every other name to
// nothing: with the proxy, the browser resolves no destination itself.
func resolverRules(spec Spec, relayIP string) string {
	return "MAP " + spec.Upstream.Hostname() + " " + relayIP + ", EXCLUDE " + relayIP + ", MAP * ~NOTFOUND"
}
