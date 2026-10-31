#!/bin/sh
# The browser container's entrypoint (ADR 0034). Everything it needs comes
# by name in the environment: APP_URL (what to open), APP_ORIGIN (the one
# origin Chromium policy allows), RESOLVER_RULES (the upstream's name mapped
# to the relay, everything else to nothing), VNC_PASSWORD, SCREEN_W and
# SCREEN_H, and CA_PEM (optional, for an https upstream). /tmp is the only
# writable place; /tmp/ready appears once the VNC server listens.
set -eu

: "${APP_URL:?}" "${APP_ORIGIN:?}" "${RESOLVER_RULES:?}" "${VNC_PASSWORD:?}"
W=${SCREEN_W:-1280}
H=${SCREEN_H:-800}
export HOME=/tmp/home
mkdir -p "$HOME" /tmp/policies

# Developer tools, when the session's grant allows them (DEVTOOLS=true, ADR
# 0037): the browser is this session's alone, so the tools see this session
# and nothing else. Otherwise they are off and devtools:// is blocked.
if [ "${DEVTOOLS:-false}" = true ]; then
  DEVTOOLS_AVAILABILITY=1 DEVTOOLS_ALLOW=',"devtools://*"' DEVTOOLS_BLOCK=''
else
  DEVTOOLS_AVAILABILITY=2 DEVTOOLS_ALLOW='' DEVTOOLS_BLOCK=',"devtools://*"'
fi

# Chromium policy: the application's origin and nothing else, with its start
# page as the home page and every new tab; Chromium's own toolbar (ADR 0037:
# an engineer sees the address and can open tabs), its internal pages, files,
# javascript: and view-source: blocked by name beside the blanket rule; no
# warning bar about the resolver rules on the command line (kiosk mode hid
# it; it would show the session's internal addressing);
# downloads, printing, extensions, sign-in, sync, saved passwords, autofill,
# safe browsing, metrics or translation. Written where Chromium reads managed
# policy on Linux, a tmpfs the gateway mounts.
cat > /etc/chromium/policies/managed/zanskar.json <<JSON
{"URLAllowlist":["$APP_ORIGIN"$DEVTOOLS_ALLOW],
 "URLBlocklist":["*","chrome://*","chrome-untrusted://*","file://*","javascript:*","view-source:*"$DEVTOOLS_BLOCK],
 "DownloadRestrictions":3,"PromptForDownloadLocation":false,"AllowFileSelectionDialogs":false,
 "DeveloperToolsAvailability":$DEVTOOLS_AVAILABILITY,"ExtensionInstallBlocklist":["*"],"PrintingEnabled":false,
 "BrowserSignin":0,"SyncDisabled":true,"PasswordManagerEnabled":false,
 "AutofillAddressEnabled":false,"AutofillCreditCardEnabled":false,
 "SafeBrowsingEnabled":false,"MetricsReportingEnabled":false,"TranslateEnabled":false,
 "DnsOverHttpsMode":"off","BackgroundModeEnabled":false,
 "AudioCaptureAllowed":false,"VideoCaptureAllowed":false,"ScreenCaptureAllowed":false,
 "DefaultGeolocationSetting":2,"DefaultNotificationsSetting":2,
 "IncognitoModeAvailability":1,"BrowserGuestModeEnabled":false,"BrowserAddPersonEnabled":false,
 "HomepageLocation":"$APP_URL","HomepageIsNewTabPage":false,"ShowHomeButton":true,
 "NewTabPageLocation":"$APP_URL","RestoreOnStartup":4,"RestoreOnStartupURLs":["$APP_URL"],
 "BookmarkBarEnabled":false,"DefaultBrowserSettingEnabled":false,"BrowserLabsEnabled":false,
 "PromotionalTabsEnabled":false,"ShoppingListEnabled":false,
 "CommandLineFlagSecurityWarningsEnabled":false}
JSON

# A private CA for an https upstream, trusted for this session only.
if [ -n "${CA_PEM:-}" ]; then
  mkdir -p "$HOME/.pki/nssdb"
  certutil -d "sql:$HOME/.pki/nssdb" -N --empty-password
  printf '%s\n' "$CA_PEM" > /tmp/upstream-ca.pem
  certutil -d "sql:$HOME/.pki/nssdb" -A -t "C,," -n upstream-ca -i /tmp/upstream-ca.pem
  rm -f /tmp/upstream-ca.pem
fi

# The VNC server: password authentication, one client at a time, the
# screen the user's window had.
printf '%s\n' "$VNC_PASSWORD" | tigervncpasswd -f > /tmp/vncpass
unset VNC_PASSWORD
Xvnc :1 -geometry "${W}x${H}" -depth 24 -rfbport 5900 -SecurityTypes VncAuth -PasswordFile /tmp/vncpass \
  -NeverShared -desktop zanskar > /tmp/xvnc.log 2>&1 &
for _ in $(seq 1 100); do
  grep -q 'Listening for VNC connections' /tmp/xvnc.log 2>/dev/null && break
  sleep 0.1
done
export DISPLAY=:1
# Clipboard between the X selections and the VNC client, under the
# gateway's clipboard policy.
vncconfig -nowin >/dev/null 2>&1 &
touch /tmp/ready

# A full browser window filling the screen, Chromium's own toolbar and tabs
# shown (ADR 0037; it was kiosk mode until 1.9). Closing the last window
# opens the start page again rather than ending the session: the session
# ends from the console. Confinement is the policy above either way.
# --enable-low-end-device-mode trims about a tenth of the memory (measured
# 2026-10-31).
while :; do
  chromium "$APP_URL" --no-first-run --no-default-browser-check \
    --window-position=0,0 --window-size="${W},${H}" --start-maximized --user-data-dir="$HOME/profile" \
    --host-resolver-rules="$RESOLVER_RULES" --password-store=basic \
    --disable-dev-shm-usage --disable-gpu --disable-background-networking \
    --disable-component-update --disable-sync --no-pings --disable-breakpad \
    --disable-features=Translate,OptimizationHints,MediaRouter \
    --enable-low-end-device-mode \
    >>/tmp/chromium.log 2>&1 || true
  sleep 1
done
