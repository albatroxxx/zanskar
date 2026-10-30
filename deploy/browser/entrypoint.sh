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

# Chromium policy: the application's origin and nothing else, with its start
# page as the home page (the console's Home button sends Alt+Home); no downloads,
# printing, developer tools, extensions, sign-in, sync, saved passwords,
# autofill, safe browsing, metrics or translation. Written where Chromium
# reads managed policy on Linux, a tmpfs the gateway mounts.
cat > /etc/chromium/policies/managed/zanskar.json <<JSON
{"URLAllowlist":["$APP_ORIGIN"],"URLBlocklist":["*"],
 "DownloadRestrictions":3,"PromptForDownloadLocation":false,"AllowFileSelectionDialogs":false,
 "DeveloperToolsAvailability":2,"ExtensionInstallBlocklist":["*"],"PrintingEnabled":false,
 "BrowserSignin":0,"SyncDisabled":true,"PasswordManagerEnabled":false,
 "AutofillAddressEnabled":false,"AutofillCreditCardEnabled":false,
 "SafeBrowsingEnabled":false,"MetricsReportingEnabled":false,"TranslateEnabled":false,
 "DnsOverHttpsMode":"off","BackgroundModeEnabled":false,
 "AudioCaptureAllowed":false,"VideoCaptureAllowed":false,"ScreenCaptureAllowed":false,
 "DefaultGeolocationSetting":2,"DefaultNotificationsSetting":2,
 "IncognitoModeAvailability":1,"BrowserGuestModeEnabled":false,"BrowserAddPersonEnabled":false,
 "HomepageLocation":"$APP_URL","HomepageIsNewTabPage":false}
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

# Kiosk mode opening the start page in an ordinary window, not an --app one:
# an app window ignores Alt+Home, and the console's Home button sends it.
# Confinement is the policy above either way.
exec chromium --kiosk "$APP_URL" --no-first-run --no-default-browser-check \
  --window-position=0,0 --window-size="${W},${H}" --user-data-dir="$HOME/profile" \
  --host-resolver-rules="$RESOLVER_RULES" --password-store=basic \
  --disable-dev-shm-usage --disable-gpu --disable-background-networking \
  --disable-component-update --disable-sync --no-pings --disable-breakpad \
  --disable-features=Translate,OptimizationHints,MediaRouter \
  >/tmp/chromium.log 2>&1
