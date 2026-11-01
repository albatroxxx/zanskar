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

# The browser window follows the screen. There is no window manager, so a
# window keeps the size it opened at; when the session's pane changes (full
# screen, a resized window) guacd resizes the X screen to match, and the
# page stopped short of the bottom, black below it (2026-11-01), or ran past
# it. Twice a second, a Chromium window at the top left about the size of
# the screen, now or before its last change (the browser window; not a menu,
# a bubble or a separate developer tools window), is made exactly the
# screen's size: Chromium also opens a window asked for at 1280x800 at
# 1279x799, a line of black at the right and the bottom.
near() {
  d=$(($1 - $2))
  [ "${d#-}" -le 8 ]
}
follow_screen() {
  last="$W $H"
  while sleep 0.5; do
    now=$(xdotool getdisplaygeometry 2>/dev/null) || continue
    for id in $(xdotool search --onlyvisible --class chromium 2>/dev/null); do
      # X, Y, WIDTH and HEIGHT, in that order.
      set -- $(xdotool getwindowgeometry --shell "$id" 2>/dev/null | sed -nE 's/^(X|Y|WIDTH|HEIGHT)=//p')
      [ $# -eq 4 ] && [ "$1" -eq 0 ] && [ "$2" -eq 0 ] || continue
      [ "$3 $4" = "$now" ] && continue
      if { near "$3" "${now% *}" && near "$4" "${now#* }"; } || { near "$3" "${last% *}" && near "$4" "${last#* }"; }; then
        xdotool windowsize "$id" ${now% *} ${now#* } windowmove "$id" 0 0 2>/dev/null || true
      fi
    done
    last=$now
  done
}
follow_screen &

# A full browser window filling the screen, Chromium's own toolbar and tabs
# shown (ADR 0037; it was kiosk mode until 1.9). Closing the last window
# opens the start page again rather than ending the session: the session
# ends from the console, and the new window takes the screen's size now,
# not the one the session started with. Confinement is the policy above
# either way. --enable-low-end-device-mode trims about a tenth of the memory
# (measured 2026-10-31).
while :; do
  screen=$(xdotool getdisplaygeometry 2>/dev/null) || screen="$W $H"
  chromium "$APP_URL" --no-first-run --no-default-browser-check \
    --window-position=0,0 --window-size="${screen% *},${screen#* }" --start-maximized --user-data-dir="$HOME/profile" \
    --host-resolver-rules="$RESOLVER_RULES" --password-store=basic \
    --disable-dev-shm-usage --disable-gpu --disable-background-networking \
    --disable-component-update --disable-sync --no-pings --disable-breakpad \
    --disable-features=Translate,OptimizationHints,MediaRouter \
    --enable-low-end-device-mode \
    >>/tmp/chromium.log 2>&1 || true
  sleep 1
done
