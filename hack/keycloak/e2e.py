"""ADR 0035 against a real Keycloak: hack/keycloak/run.sh runs this.

Inside a container on a private network: Keycloak is https://kc:8443, the
gateway listens on 127.0.0.1:18443 in this same container (inside.sh). It
plays a browser with urllib and a cookie jar, following each redirect by
hand, and stops at the first check that fails.
"""
import base64, hashlib, hmac, html, http.cookiejar, json, re, ssl, struct, sys, time, urllib.error, urllib.parse, urllib.request

KC = "https://kc:8443"
ZK = "http://127.0.0.1:18443"
CTX = ssl.create_default_context(cafile="/work/kc.pem")
STEP = 0


def say(msg):
    global STEP
    STEP += 1
    print(f"[{STEP:02d}] {msg}", flush=True)


def check(cond, msg):
    if not cond:
        print("FAIL:", msg, flush=True)
        sys.exit(1)
    print("     ok:", msg, flush=True)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Browser:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), urllib.request.HTTPSHandler(context=CTX), NoRedirect)
        self.csrf = ""

    def req(self, method, url, data=None, headers=None, form=None):
        h = dict(headers or {})
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form).encode()
            h["Content-Type"] = "application/x-www-form-urlencoded"
        elif data is not None:
            body = json.dumps(data).encode()
            h["Content-Type"] = "application/json"
        if url.startswith(ZK) and method != "GET":
            h["Origin"] = ZK
            if self.csrf:
                h["X-CSRF-Token"] = self.csrf
        r = urllib.request.Request(url, data=body, method=method, headers=h)
        try:
            res = self.op.open(r, timeout=30)
        except urllib.error.HTTPError as e:
            res = e
        return res.status, dict(res.headers), res.read().decode("utf-8", "replace")

    def follow(self, url, limit=15):
        """GET url and follow redirects; returns the final (status, headers, body, url) and every hop."""
        hops = []
        method, form = "GET", None
        for _ in range(limit):
            st, hd, body = self.req(method, url, form=form)
            hops.append((st, url))
            if st in (301, 302, 303, 307) and hd.get("Location"):
                url = urllib.parse.urljoin(url, hd["Location"])
                method, form = "GET", None
                continue
            return st, hd, body, url, hops
        raise RuntimeError("too many redirects")

    def api(self, method, path, data=None):
        st, _, body = self.req(method, ZK + path, data=data)
        try:
            return st, json.loads(body) if body else None
        except json.JSONDecodeError:
            return st, body


def kc_post(b, action, form):
    """POST a Keycloak form and follow Keycloak's own redirects. Returns
    (body, None) on a Keycloak page, or (None, url) once it sends the browser
    back to Zanskar."""
    st, hd, body = b.req("POST", action, form=form)
    for _ in range(10):
        if st not in (301, 302, 303):
            return body, None
        loc = urllib.parse.urljoin(action, hd["Location"])
        if loc.startswith(ZK):
            return None, loc
        st, hd, body = b.req("GET", loc)
        action = loc
    raise RuntimeError("too many redirects")


def totp(key, at=None):
    counter = int((at or time.time()) // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = digest[-1] & 0x0F
    return f"{(struct.unpack('>I', digest[o:o + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


def fresh_code(key, used):
    """A code not used yet: wait for the next period if the current one was."""
    while True:
        c = totp(key)
        if c not in used:
            used.add(c)
            return c
        time.sleep(2)


def form_of(body, form_id=None):
    """The action and every named input of a Keycloak form."""
    m = re.search(r'<form[^>]*id="%s"[^>]*>(.*?)</form>' % re.escape(form_id), body, re.S) if form_id else re.search(r"<form[^>]*>(.*?)</form>", body, re.S)
    if not m:
        return None, {}
    tag = re.search(r"<form[^>]*>", m.group(0)).group(0)
    action = html.unescape(re.search(r'action="([^"]+)"', tag).group(1))
    fields = {}
    for inp in re.finditer(r"<input[^>]*>", m.group(1)):
        t = inp.group(0)
        n = re.search(r'name="([^"]+)"', t)
        if n:
            v = re.search(r'value="([^"]*)"', t)
            fields[n.group(1)] = html.unescape(v.group(1)) if v else ""
    return action, fields


# ---------------------------------------------------------------- Keycloak setup
kc = Browser()


def kc_admin_token():
    st, _, body = kc.req("POST", KC + "/realms/master/protocol/openid-connect/token", form={"client_id": "admin-cli", "username": "admin", "password": "admin", "grant_type": "password"})
    return json.loads(body)["access_token"]


def kc_api(method, path, data=None):
    st, hd, body = kc.req(method, KC + "/admin/realms" + path, data=data, headers={"Authorization": "Bearer " + kc_admin_token()})
    return st, (json.loads(body) if body.strip().startswith(("[", "{")) else body), hd


say("Keycloak: realm, client with a service account (view-users), three people")
for _ in range(60):
    try:
        if kc.req("GET", KC + "/realms/master")[0] == 200:
            break
    except Exception:
        pass
    time.sleep(2)
kc_api("DELETE", "/zanskar")  # start from nothing on every run
kc_api("POST", "", {"realm": "zanskar", "enabled": True})
kc_api("POST", "/zanskar/clients", {"clientId": "zanskar", "enabled": True, "publicClient": False, "secret": "zsecret", "serviceAccountsEnabled": True,
                                    "standardFlowEnabled": True, "redirectUris": [ZK + "/api/v1/auth/oidc/*"]})  # no post-logout URI registered: the callback serves
cid = kc_api("GET", "/zanskar/clients?clientId=zanskar")[1][0]["id"]
sa = kc_api("GET", f"/zanskar/clients/{cid}/service-account-user")[1]["id"]
rm = kc_api("GET", "/zanskar/clients?clientId=realm-management")[1][0]["id"]
role = kc_api("GET", f"/zanskar/clients/{rm}/roles/view-users")[1]
check(kc_api("POST", f"/zanskar/users/{sa}/role-mappings/clients/{rm}", [role])[0] == 204, "service account granted view-users")
people = {}
for u in ("alice", "bob", "carol"):
    rep = {"username": u, "enabled": True, "email": f"{u}@corp.example", "emailVerified": True, "firstName": u.title(), "lastName": "Test",
           "credentials": [{"type": "password", "value": f"pw-{u}", "temporary": False}]}
    if u == "alice":
        rep["requiredActions"] = ["CONFIGURE_TOTP"]
    st, _, hd = kc_api("POST", "/zanskar/users", rep)
    people[u] = hd["Location"].rsplit("/", 1)[1]
check(len(people) == 3, "alice (must set up Keycloak OTP), bob, carol created in the realm")

# ---------------------------------------------------------------- Zanskar admin
z = Browser()
say("Zanskar: the local admin signs in (MFA required for local accounts)")
st, out = z.api("POST", "/api/v1/auth/login", {"username": "root", "password": "bootstrap passphrase 2026"})
check(st == 200 and out["status"] == "mfa_enrollment_required", f"root owes an authenticator: {out}")
z.csrf = out["csrf_token"]
st, enr = z.api("POST", "/api/v1/auth/mfa/totp/enroll", {})
root_key = base64.b32decode(enr["secret"] + "=" * (-len(enr["secret"]) % 8))
root_used = set()
st, out = z.api("POST", "/api/v1/auth/mfa/totp/confirm", {"code": fresh_code(root_key, root_used)})
check(st == 200, f"root enrolled: {st}")
z.csrf = z.api("GET", "/api/v1/auth/me")[1]["csrf_token"]

say("Zanskar: add Keycloak as a provider with user sync on")
st, prov = z.api("POST", "/api/v1/identity-providers", {"name": "Keycloak", "type": "oidc", "enabled": True, "config": {
    "oidc": {"issuer": KC + "/realms/zanskar", "client_id": "zanskar", "client_secret": "zsecret"},
    "auto_provision": True, "default_roles": ["user"], "sync_users": True, "sync_minutes": 5}})
check(st == 201, f"provider created: {st} {prov}")
pid = prov["id"]

say("Joiners: Sync now creates everyone in the realm before any sign-in")
st, sync = z.api("POST", f"/api/v1/identity-providers/{pid}/sync", {})
last = sync["last"]
check(st == 200 and last["ok"] and last["listed"] == 3 and last["created"] == 3, f"sync: {last}")
st, users = z.api("GET", "/api/v1/users?limit=100")
synced = {u["username"]: u for u in users["items"] if u.get("idp_id") == pid}
check(set(synced) == {"alice", "bob", "carol"}, f"accounts: {sorted(synced)}")
check(synced["alice"]["external_id"] == people["alice"] and synced["alice"]["display_name"] == "Alice Test", "alice's account is linked to her Keycloak id, named as Keycloak names her")

# ---------------------------------------------------------------- alice signs in
alice = Browser()
alice_otp = {"key": None, "used": set()}


def sign_in(expect_credentials=True, first=False):
    st, hd, body, url, hops = alice.follow(ZK + f"/api/v1/auth/oidc/{pid}/start?next=%2Fhome")
    if not expect_credentials:
        return st, url, hops, body
    action, fields = form_of(body, "kc-form-login")
    check(action is not None and "username" in fields, f"Keycloak asks for the username and password (landed on {url.split('?')[0]})")
    body, back = kc_post(alice, action, {"username": "alice", "password": "pw-alice", "credentialId": ""})
    if first:
        forms = re.findall(r'<form[^>]*id="([^"]+)"', body or "")
        action, fields = form_of(body or "", forms[0] if forms else None)
        check(action is not None and fields.get("totpSecret"), f"Keycloak asks alice to set up its OTP (her first sign-in; form {forms})")
        alice_otp["key"] = fields["totpSecret"].encode()
        fields.update({"totp": fresh_code(alice_otp["key"], alice_otp["used"]), "userLabel": "phone"})
        body, back = kc_post(alice, action, fields)
    else:
        forms = re.findall(r'<form[^>]*id="([^"]+)"', body or "")
        action, fields = form_of(body or "", forms[0] if forms else None)
        check(action is not None and "otp" in fields, f"Keycloak asks for its one-time code (form {forms})")
        fields["otp"] = fresh_code(alice_otp["key"], alice_otp["used"])
        body, back = kc_post(alice, action, fields)
    check(back is not None and back.startswith(ZK + f"/api/v1/auth/oidc/{pid}/callback"), "Keycloak sends her back to Zanskar's callback")
    st, hd, body, url, hops = alice.follow(back)
    return st, url, hops, body


say("alice's first sign-in: Keycloak password, Keycloak OTP set-up, and nothing from Zanskar")
st, url, hops, _ = sign_in(first=True)
check(url == ZK + "/home", f"landed on /home, not the Zanskar code step: {url}")
st, me = alice.api("GET", "/api/v1/auth/me")
check(st == 200 and me["pending"] is None and me["user"]["id"] == synced["alice"]["id"], "full session, on the account the sync created")
alice.csrf = me["csrf_token"]

say("alice signs out: Zanskar names Keycloak's sign-out page, and Keycloak ends its session")
st, out = alice.api("POST", "/api/v1/auth/logout")
check(st == 200 and out.get("redirect", "").startswith(KC + "/realms/zanskar/protocol/openid-connect/logout?"), f"logout answer: {out}")
q = urllib.parse.parse_qs(urllib.parse.urlparse(out["redirect"]).query)
check(q.get("id_token_hint") and q.get("client_id") == ["zanskar"] and q.get("post_logout_redirect_uri") == [ZK + f"/api/v1/auth/oidc/{pid}/callback"] and q.get("state") == ["signed-out"], "id_token_hint, client_id, and the callback (already registered) as the way back")
st, hd, body, url, hops = alice.follow(out["redirect"])
check(url == ZK + "/login", f"no confirmation page: Keycloak went straight back to /login ({[h[1].split('?')[0] for h in hops]})")
check(alice.api("GET", "/api/v1/auth/me")[0] == 401, "the Zanskar session is gone")

say("alice signs in again: Keycloak asks for the password and its code again (the reported bug)")
st, url, hops, _ = sign_in()
check(url == ZK + "/home", f"landed on /home: {url}")

say("Leavers: bob is disabled in Keycloak and carol deleted; the sync disables both and ends their sessions")
bob = Browser()
st, hd, body, url, _ = bob.follow(ZK + f"/api/v1/auth/oidc/{pid}/start")
action, fields = form_of(body, "kc-form-login")
_, back = kc_post(bob, action, {"username": "bob", "password": "pw-bob", "credentialId": ""})
bob.follow(back)
check(bob.api("GET", "/api/v1/auth/me")[0] == 200, "bob is signed in to Zanskar")
rep = kc_api("GET", f"/zanskar/users/{people['bob']}")[1]
rep["enabled"] = False
kc_api("PUT", f"/zanskar/users/{people['bob']}", rep)
kc_api("DELETE", f"/zanskar/users/{people['carol']}")
st, sync = z.api("POST", f"/api/v1/identity-providers/{pid}/sync", {})
last = sync["last"]
check(last["ok"] and last["listed"] == 1 and last["disabled"] == 2, f"sync: {last}")
check(bob.api("GET", "/api/v1/auth/me")[0] == 401, "bob's Zanskar session ended with the sync, not 12 hours later")
st, u = z.api("GET", f"/api/v1/users/{synced['bob']['id']}")
check(u["status"] == "disabled" and u.get("directory_removed_at"), f"bob disabled and marked: {u['status']}")

say("Returners: bob is enabled in Keycloak again; the sync enables his account")
rep["enabled"] = True
kc_api("PUT", f"/zanskar/users/{people['bob']}", rep)
st, sync = z.api("POST", f"/api/v1/identity-providers/{pid}/sync", {})
check(sync["last"]["enabled"] == 1, f"sync: {sync['last']}")
st, u = z.api("GET", f"/api/v1/users/{synced['bob']['id']}")
check(u["status"] == "active" and not u.get("directory_removed_at"), "bob active again")

say("The list shows the provider's last run")
st, lst = z.api("GET", "/api/v1/identity-providers")
row = [p for p in lst["items"] if p["id"] == pid][0]
check(row["sync"]["last"]["enabled"] == 1 and row["sync"]["interval_minutes"] == 5, "sync state in the list")

say("Audit trail")
st, ev = z.api("GET", "/api/v1/audit/events?action=idp.sync&limit=10")
check(st == 200 and len(ev["items"]) == 3, f"three idp.sync events, one per Sync now: {len(ev['items']) if isinstance(ev, dict) else ev}")
st, ev = z.api("GET", "/api/v1/audit/events?action=user.logout&limit=5")
check(any('"provider_sign_out":"true"' in json.dumps(e.get("details"), separators=(",", ":")) for e in ev["items"]), "alice's logout is recorded with provider_sign_out")
st, ev = z.api("GET", "/api/v1/audit/events?action=user.login&limit=50")
check(not [e for e in ev["items"] if e["outcome"] != "success"], "no failed sign-in recorded on the way back from Keycloak's sign-out")
print("\nALL CHECKS PASSED", flush=True)
