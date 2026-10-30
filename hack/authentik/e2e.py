"""ADR 0035 against a real Authentik: a second vendor, to show the identity
features are standard, not Keycloak's. hack/authentik/run.sh runs this.

On a private network: Authentik behind TLS as https://ak, the gateway on
http://zk:18443 in this container. Authentik pushes users to the gateway
over SCIM 2.0; the scripted browser signs in over OIDC with an email-form
username, drives Authentik's flow executor API (its login page is a single
page application over that API), and signs out.
"""
import base64, hashlib, hmac, http.cookiejar, json, os, re, secrets, ssl, struct, sys, time, urllib.error, urllib.parse, urllib.request

AK = "https://ak"
AK_API = AK + "/api/v3"
ZK = "http://zk:18443"
CTX = ssl.create_default_context(cafile="/w/ak.pem")
AK_TOKEN = os.environ["AK_TOKEN"]
ROOT_PW = os.environ["ZANSKAR_E2E_ROOT_PW"]
ALICE = "alice@corp.example"
ALICE_PW = secrets.token_urlsafe(18)
# MODE "logout" (the recommended set-up): Authentik's provider sign-out ends
# Authentik's own session. MODE "prompt": Authentik's default provider flow,
# which keeps it, and Zanskar asks for prompt=login at every sign-in.
MODE = os.environ.get("AK_MODE", "logout")
CLIENT_ID, CLIENT_SECRET = "zanskar", secrets.token_urlsafe(32)
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


def wait_for(what, fn, timeout=90):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(2)
    print("FAIL: timed out waiting for", what, flush=True)
    sys.exit(1)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Browser:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), urllib.request.HTTPSHandler(context=CTX), NoRedirect)
        self.csrf = ""

    def cookie(self, name):
        for c in self.jar:
            if c.name == name:
                return c.value
        return ""

    def req(self, method, url, data=None, headers=None):
        h = dict(headers or {})
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            h["Content-Type"] = "application/json"
        if url.startswith(ZK) and method != "GET":
            h["Origin"] = ZK
            if self.csrf:
                h["X-CSRF-Token"] = self.csrf
        if url.startswith(AK) and method != "GET":
            h["X-authentik-CSRF"] = self.cookie("authentik_csrf")
            h["Referer"] = AK + "/"
        r = urllib.request.Request(url, data=body, method=method, headers=h)
        try:
            res = self.op.open(r, timeout=30)
        except urllib.error.HTTPError as e:
            res = e
        return res.status, res.headers, res.read().decode("utf-8", "replace")

    def api(self, method, path, data=None):
        st, _, body = self.req(method, ZK + path, data=data)
        try:
            return st, json.loads(body) if body else None
        except json.JSONDecodeError:
            return st, body

    def follow(self, url, limit=20):
        """GET url and follow redirects, through Authentik's flow pages:
        each one is driven by its executor API until it redirects on.
        Returns the final URL and the last flow challenge seen, if the
        browser stopped on one that needs input."""
        for _ in range(limit):
            st, hd, body = self.req("GET", url)
            if st in (301, 302, 303, 307) and hd.get("Location"):
                url = urllib.parse.urljoin(url, hd["Location"])
                continue
            m = re.match(re.escape(AK) + r"/if/flow/([^/]+)/\??(.*)$", url)
            if m:
                return url, self.flow(m.group(1), m.group(2))
            return url, None
        raise RuntimeError("too many redirects")

    def flow(self, slug, query):
        url = f"{AK_API}/flows/executor/{slug}/?query={urllib.parse.quote(query)}"
        st, hd, body = self.req("GET", url)
        for _ in range(5):
            loc = hd.get("Location") if st in (301, 302, 303) else None
            if not loc:
                break
            loc = urllib.parse.urljoin(url, loc)
            if not loc.startswith(AK_API + "/flows/executor/"):
                # The flow is done and sends the browser on.
                return {"slug": slug, "query": query, "challenge": {"component": "xak-flow-redirect", "to": loc}}
            url = loc
            st, hd, body = self.req("GET", url)
        return {"slug": slug, "query": query, "challenge": json.loads(body)}

    def answer(self, f, data):
        url = f"{AK_API}/flows/executor/{f['slug']}/?query={urllib.parse.quote(f['query'])}"
        st, hd, body = self.req("POST", url, data=data)
        # The executor answers a stage with a redirect to fetch the next one.
        for _ in range(5):
            if st not in (301, 302, 303) or not hd.get("Location"):
                break
            url = urllib.parse.urljoin(url, hd["Location"])
            st, hd, body = self.req("GET", url)
        try:
            f["challenge"] = json.loads(body)
        except json.JSONDecodeError:
            raise RuntimeError(f"flow executor answered {st}: {body[:300]}")
        return f


def ak(method, path, data=None):
    h = {"Authorization": "Bearer " + AK_TOKEN, "Content-Type": "application/json", "Accept": "application/json"}
    r = urllib.request.Request(AK_API + path, data=json.dumps(data).encode() if data is not None else None, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, context=CTX, timeout=30) as res:
            body = res.read().decode()
            return res.status, json.loads(body) if body else None
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        return e.status, (json.loads(body) if body.startswith(("{", "[")) else body)


def one(path):
    st, out = ak("GET", path)
    return out["results"][0] if out and out.get("results") else None


def totp(key):
    counter = int(time.time() // 30)
    digest = hmac.digest(key, struct.pack(">Q", counter), "sha1")  # NOSONAR: RFC 6238 TOTP is HMAC-SHA-1, not a choice
    o = digest[-1] & 0x0F
    return f"{(struct.unpack('>I', digest[o:o + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


# ---------------------------------------------------------------- Zanskar
z = Browser()
say("Zanskar: the local admin signs in; it adds Authentik with SCIM on, and makes a SCIM token")
st, out = z.api("POST", "/api/v1/auth/login", {"username": "root", "password": ROOT_PW})
check(st == 200 and out["status"] == "mfa_enrollment_required", "root owes an authenticator (MFA is required for local accounts)")
z.csrf = out["csrf_token"]
st, enr = z.api("POST", "/api/v1/auth/mfa/totp/enroll", {})
st, _ = z.api("POST", "/api/v1/auth/mfa/totp/confirm", {"code": totp(base64.b32decode(enr["secret"] + "=" * (-len(enr["secret"]) % 8)))})
z.csrf = z.api("GET", "/api/v1/auth/me")[1]["csrf_token"]
st, prov = z.api("POST", "/api/v1/identity-providers", {"name": "Authentik", "type": "oidc", "enabled": True, "config": {
    "oidc": {"issuer": AK + "/application/o/zanskar/", "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "prompt_login": MODE == "prompt"},
    "auto_provision": True, "default_roles": ["user"], "scim": True}})
check(st == 201, f"provider created: {st}")
pid = prov["id"]
st, tok = z.api("POST", f"/api/v1/identity-providers/{pid}/scim-token")
check(st == 200 and tok["token"].startswith("zscim_"), "SCIM token made")

# ---------------------------------------------------------------- Authentik
say("Authentik: an OIDC provider and application for Zanskar, a SCIM provider pushing to it")
for path, key in (("/core/applications/?slug=zanskar", "slug"), ("/providers/oauth2/?name=zanskar", "pk"), ("/providers/scim/?name=zanskar-scim", "pk")):
    old = one(path)
    if old:
        base = path.split("?")[0]
        ak("DELETE", f"{base}{old[key]}/")
flow = lambda slug: one(f"/flows/instances/?slug={slug}")["pk"]
scopes = [m["pk"] for m in ak("GET", "/propertymappings/provider/scope/?page_size=100")[1]["results"]
          if m["managed"] in ("goauthentik.io/providers/oauth2/scope-openid", "goauthentik.io/providers/oauth2/scope-email", "goauthentik.io/providers/oauth2/scope-profile")]
key = one("/crypto/certificatekeypairs/?name=" + urllib.parse.quote("authentik Self-signed Certificate"))["pk"]
st, op = ak("POST", "/providers/oauth2/", {
    "name": "zanskar", "authorization_flow": flow("default-provider-authorization-implicit-consent"),
    # Authentik's default provider invalidation flow ends only the
    # application's session and shows a page; its own session survives.
    # default-invalidation-flow logs the person out of Authentik too.
    "invalidation_flow": flow("default-invalidation-flow" if MODE == "logout" else "default-provider-invalidation-flow"), "client_type": "confidential",
    "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "signing_key": key, "property_mappings": scopes, "grant_types": ["authorization_code", "refresh_token"],
    # The callback once for sign-in and once as the way back from sign-out:
    # Authentik keeps the two lists apart, as Okta does.
    "redirect_uris": [{"matching_mode": "strict", "url": ZK + f"/api/v1/auth/oidc/{pid}/callback", "redirect_uri_type": "authorization"},
                      {"matching_mode": "strict", "url": ZK + f"/api/v1/auth/oidc/{pid}/callback", "redirect_uri_type": "logout"}]})
check(st == 201, f"OAuth2 provider: {st} {op if st != 201 else ''}")
scim_maps = {m["managed"]: m["pk"] for m in ak("GET", "/propertymappings/provider/scim/?page_size=100")[1]["results"]}
st, sp = ak("POST", "/providers/scim/", {
    "name": "zanskar-scim", "url": ZK + f"/api/v1/scim/{pid}", "token": tok["token"], "verify_certificates": False,
    "property_mappings": [scim_maps["goauthentik.io/providers/scim/user"]], "property_mappings_group": [],
    "exclude_users_service_account": True})
check(st == 201, f"SCIM provider: {st} {sp if st != 201 else ''}")
st, app = ak("POST", "/core/applications/", {"name": "Zanskar", "slug": "zanskar", "provider": op["pk"], "backchannel_providers": [sp["pk"]]})
check(st == 201, f"application: {st} {app if st != 201 else ''}")

say("Joiner: alice is created in Authentik; Authentik pushes her to Zanskar over SCIM before she signs in")
old = one("/core/users/?username=" + urllib.parse.quote(ALICE))
if old:
    ak("DELETE", f"/core/users/{old['pk']}/")
st, alice_ak = ak("POST", "/core/users/", {"username": ALICE, "name": "Alice Smith", "email": ALICE, "is_active": True, "path": "users"})
check(st == 201, f"alice in Authentik: {st}")
ak("POST", f"/core/users/{alice_ak['pk']}/set_password/", {"password": ALICE_PW})


def zanskar_user(username):
    st, out = z.api("GET", "/api/v1/users?limit=200")
    for u in out.get("items", []):
        if u["username"] == username:
            return u
    return None


alice = wait_for("alice to be pushed", lambda: zanskar_user(ALICE))
check(alice["idp_id"] == pid and not alice.get("external_id") and alice.get("scim_external_id"), f"alice exists in Zanskar, linked to Authentik, not yet signed in: {alice}")

# ---------------------------------------------------------------- sign-in
def sign_in(b, expect_password=True):
    """Start a sign-in through Authentik and drive its flows. Returns the
    final URL and the stages Authentik asked for."""
    url, f = b.follow(ZK + f"/api/v1/auth/oidc/{pid}/start?next=%2Fhome")
    asked = []
    for _ in range(10):
        if f is None:
            return url, asked
        c = f["challenge"]
        comp = c.get("component")
        asked.append(comp)
        if comp == "ak-stage-identification":
            f = b.answer(f, {"component": comp, "uid_field": ALICE})
        elif comp == "ak-stage-password":
            f = b.answer(f, {"component": comp, "password": ALICE_PW})
        elif comp == "xak-flow-redirect":
            url, f = b.follow(urllib.parse.urljoin(AK, c["to"]))
        else:
            print("     unexpected challenge:", json.dumps(c)[:400], flush=True)
            return url, asked
    return url, asked


say("alice signs in with Authentik: its username and password, and nothing asked by Zanskar")
alice_b = Browser()
url, asked = sign_in(alice_b)
print("     Authentik asked:", asked, "ended at", url[:160], flush=True)
check("ak-stage-identification" in asked and "ak-stage-password" in asked, "Authentik asked for the username and password")
check(url == ZK + "/home", f"landed on /home, with MFA required for local accounts and none asked: {url}")
st, me = alice_b.api("GET", "/api/v1/auth/me")
check(st == 200 and me["pending"] is None and me["user"]["id"] == alice["id"] and me["user"]["external_id"], "full session, on the account SCIM made, now bound to her Authentik subject")
alice_b.csrf = me["csrf_token"]

say("alice signs out: Zanskar sends her to Authentik's end-session endpoint")
st, out = alice_b.api("POST", "/api/v1/auth/logout")
check(st == 200 and out.get("redirect", "").startswith(AK + "/application/o/zanskar/end-session/"), f"logout names Authentik's end-session endpoint: {str(out)[:120]}")
url, f = alice_b.follow(out["redirect"])
stages = []
for _ in range(6):
    if f is None:
        break
    c = f["challenge"]
    stages.append(c.get("component"))
    if c.get("component") == "xak-flow-redirect":
        url, f = alice_b.follow(urllib.parse.urljoin(AK, c["to"]))
    else:
        print("     stopped on", json.dumps(c)[:300], flush=True)
        break
print(f"     Authentik's sign-out: stages {stages}, ended at {url[:120]}", flush=True)
check(alice_b.api("GET", "/api/v1/auth/me")[0] == 401, "the Zanskar session is gone")
SIGNED_OUT_BACK = url.startswith(ZK + "/login")

if MODE == "prompt":
    # Past the minute of clock skew Zanskar allows on auth_time, so an old
    # Authentik session is old enough to tell apart from a fresh one.
    print("     waiting 70 s so her Authentik session is older than the skew allowance", flush=True)
    time.sleep(70)
say("alice signs in again: Authentik asks for her password again" + (" (prompt=login; Authentik kept its session)" if MODE == "prompt" else ""))
url, asked = sign_in(alice_b)
print("     Authentik asked:", asked, "and the browser landed on", url, flush=True)
if MODE == "prompt" and "ak-stage-password" not in asked:
    # Authentik 2026.8 ignores prompt=login and max_age=0 and hands back its
    # session; Zanskar sees the old auth_time and refuses the sign-in.
    check(url == ZK + "/login?error=reauth_not_done", "Authentik did not ask again, so Zanskar refused the stale sign-in rather than take it")
    alice_b = Browser()  # a fresh browser: no Authentik session to reuse
    url, asked = sign_in(alice_b)
check("ak-stage-password" in asked and url == ZK + "/home", "the password was asked again, and she is back in")
alice_b.csrf = alice_b.api("GET", "/api/v1/auth/me")[1]["csrf_token"]

say("Leaver: alice is deactivated in Authentik; it pushes that, and Zanskar disables her and ends her session")
st, _ = ak("PATCH", f"/core/users/{alice_ak['pk']}/", {"is_active": False})
check(st == 200, "deactivated in Authentik")
gone = wait_for("alice to be disabled", lambda: (lambda u: u if u and u["status"] == "disabled" else None)(zanskar_user(ALICE)))
check(gone.get("directory_removed_at"), "disabled and marked as the provider's doing")
check(alice_b.api("GET", "/api/v1/auth/me")[0] == 401, "her open session ended")

say("Returner: alice is activated in Authentik again; Zanskar enables her")
ak("PATCH", f"/core/users/{alice_ak['pk']}/", {"is_active": True})
wait_for("alice to be enabled", lambda: (lambda u: u if u and u["status"] == "active" else None)(zanskar_user(ALICE)))
check(True, "enabled again")

say("Deleted: alice is deleted in Authentik; Zanskar disables the account and keeps its history")
ak("DELETE", f"/core/users/{alice_ak['pk']}/")
deleted = wait_for("alice to be deleted", lambda: (lambda u: u if u and u.get("scim_deleted_at") else None)(zanskar_user(ALICE)))
check(deleted["status"] == "disabled", "disabled, marked deleted, kept")

say("Audit trail")
st, ev = z.api("GET", "/api/v1/audit/events?limit=200")
via = [e for e in ev["items"] if '"via":"scim"' in json.dumps(e.get("details"), separators=(",", ":"))]
check(any(e["action"] == "user.create" for e in via) and sum(e["action"] == "user.update" for e in via) >= 3, f"SCIM changes recorded: {[e['action'] for e in via]}")
fails = [e["details"].get("reason") for e in ev["items"] if e["action"] == "user.login" and e["outcome"] != "success"]
check(fails == ([] if MODE == "logout" else ["reauth_not_done"]) or (MODE == "prompt" and fails == []), f"failed sign-ins recorded: {fails}")
print("\nALL CHECKS PASSED", "(sign-out came back to /login)" if SIGNED_OUT_BACK else "(sign-out ended on Authentik's page)", flush=True)
