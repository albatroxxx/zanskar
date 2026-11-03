// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// The acceptance tests run Terraform against a real gateway, built from
// this repository and started on SQLite in a temporary directory, with an
// API token minted through its own API (ADR 0044). TF_ACC=1 runs them;
// they need the terraform binary and a Go toolchain.

var factories = map[string]func() (tfprotov6.ProviderServer, error){
	"zanskar": providerserver.NewProtocol6WithError(New("test")()),
}

var gw struct {
	once  sync.Once
	err   error
	url   string
	token string
	cred  string // a credential's name in the vault
	cmd   *exec.Cmd
	dir   string
}

func TestMain(m *testing.M) {
	code := m.Run()
	if gw.cmd != nil && gw.cmd.Process != nil {
		_ = gw.cmd.Process.Kill()
		_ = gw.cmd.Wait()
	}
	if gw.dir != "" {
		_ = os.RemoveAll(gw.dir)
	}
	os.Exit(code)
}

// gateway starts the gateway once for the run and returns its address and
// a token.
func gateway(t *testing.T) (string, string) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC=1 runs the acceptance tests against a gateway built from this repository")
	}
	gw.once.Do(func() { gw.err = startGateway() })
	if gw.err != nil {
		t.Fatal(gw.err)
	}
	return gw.url, gw.token
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func startGateway() error {
	dir, err := os.MkdirTemp("", "zanskar-tf-acc-")
	if err != nil {
		return err
	}
	gw.dir = dir
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		return err
	}
	bin := filepath.Join(dir, "zanskar")
	build := exec.Command("go", "build", "-o", bin, "./cmd/zanskar")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		return fmt.Errorf("build the gateway: %w\n%s", err, out)
	}
	port, err := freePort()
	if err != nil {
		return err
	}
	env := append(os.Environ(),
		"ZANSKAR_DB_DSN=file:"+filepath.Join(dir, "z.db")+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)",
		fmt.Sprintf("ZANSKAR_LISTEN_ADDR=127.0.0.1:%d", port),
		"ZANSKAR_REQUIRE_MFA=false", "ZANSKAR_LOG_FORMAT=text", "ZANSKAR_RECORDINGS_DIR="+filepath.Join(dir, "rec"),
		"ZANSKAR_MASTER_KEY_FILE=", "ZANSKAR_TLS_MODE=", "ZANSKAR_UPDATE_CHECK=false")
	run := func(extra []string, args ...string) ([]byte, error) {
		c := exec.Command(bin, args...)
		c.Env = append(slices.Clone(env), extra...)
		return c.CombinedOutput()
	}
	if out, err := run(nil, "migrate"); err != nil {
		return fmt.Errorf("migrate: %w\n%s", err, out)
	}
	// A throwaway passphrase for a gateway that lives as long as the test.
	const password, passwordVar = "acceptance passphrase 2026", "ZANSKAR_ADMIN_PASSWORD"
	if out, err := run([]string{passwordVar + "=" + password}, "admin", "create", "--username", "root", "--name", "Root"); err != nil {
		return fmt.Errorf("admin create: %w\n%s", err, out)
	}
	key, err := run(nil, "keygen")
	if err != nil {
		return fmt.Errorf("keygen: %w\n%s", err, key)
	}
	env = append(env, "ZANSKAR_MASTER_KEY="+strings.TrimSpace(string(key)))
	log, err := os.Create(filepath.Join(dir, "gateway.log"))
	if err != nil {
		return err
	}
	gw.cmd = exec.Command(bin, "serve")
	gw.cmd.Env, gw.cmd.Stdout, gw.cmd.Stderr = env, log, log
	if err := gw.cmd.Start(); err != nil {
		return err
	}
	gw.url = fmt.Sprintf("http://127.0.0.1:%d", port)
	for i := 0; ; i++ {
		res, err := http.Get(gw.url + "/readyz")
		if err == nil {
			_ = res.Body.Close()
			if res.StatusCode == 200 {
				break
			}
		}
		if i > 150 {
			b, _ := os.ReadFile(filepath.Join(dir, "gateway.log")) // #nosec G304 -- the test's own temp file
			return fmt.Errorf("the gateway did not come up:\n%s", b)
		}
		time.Sleep(200 * time.Millisecond)
	}
	// Signed in as the administrator, as a person would be: make a token
	// and put a credential in the vault for the targets to name.
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar}
	csrf := ""
	call := func(method, path string, in, out any) error {
		b, _ := json.Marshal(in)
		req, _ := http.NewRequestWithContext(context.Background(), method, gw.url+"/api/v1"+path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		res, err := hc.Do(req)
		if err != nil {
			return err
		}
		defer func() { _ = res.Body.Close() }()
		if res.StatusCode >= 300 {
			var e map[string]any
			_ = json.NewDecoder(res.Body).Decode(&e)
			return fmt.Errorf("%s %s: %d %v", method, path, res.StatusCode, e)
		}
		if out != nil {
			return json.NewDecoder(res.Body).Decode(out)
		}
		return nil
	}
	var login struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := call("POST", "/auth/login", map[string]string{"username": "root", "password": password}, &login); err != nil {
		return err
	}
	csrf = login.CSRFToken
	var tok struct {
		Secret string `json:"secret"`
	}
	if err := call("POST", "/admin/api-tokens", map[string]any{"name": "acceptance", "days": 1}, &tok); err != nil {
		return err
	}
	gw.token = tok.Secret
	gw.cred = "acc-linux"
	return call("POST", "/credentials", map[string]any{"name": gw.cred, "type": "password", "mode": "vaulted", "username": "svc", "password": "pw-acceptance"}, nil)
}

func providerBlock(url, token string) string {
	return fmt.Sprintf("provider \"zanskar\" {\n  url   = %q\n  token = %q\n}\n", url, token)
}

func TestAccGroup(t *testing.T) {
	url, token := gateway(t)
	cfg := func(desc string) string {
		return providerBlock(url, token) + fmt.Sprintf(`
resource "zanskar_group" "ops" {
  name        = "acc-ops"
  description = %q
}
data "zanskar_group" "ops" {
  name       = zanskar_group.ops.name
  depends_on = [zanskar_group.ops]
}
`, desc)
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{Config: cfg("operators"), Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("zanskar_group.ops", "name", "acc-ops"),
				resource.TestCheckResourceAttr("zanskar_group.ops", "description", "operators"),
				resource.TestCheckResourceAttrPair("data.zanskar_group.ops", "id", "zanskar_group.ops", "id"),
			)},
			{Config: cfg("operators, on call"), Check: resource.TestCheckResourceAttr("zanskar_group.ops", "description", "operators, on call")},
			{ResourceName: "zanskar_group.ops", ImportState: true, ImportStateVerify: true},
		},
	})
}

func TestAccTargets(t *testing.T) {
	url, token := gateway(t)
	cfg := func(env string) string {
		return providerBlock(url, token) + fmt.Sprintf(`
data "zanskar_credential" "linux" {
  name = %q
}
resource "zanskar_target" "web" {
  name        = "acc-web-1"
  address     = "10.20.0.5"
  os_family   = "linux"
  tags        = { env = %q, tier = "web" }
  credentials = { ssh = data.zanskar_credential.linux.id }
  notes       = "managed by terraform"
}
resource "zanskar_target" "db" {
  name          = "acc-orders-db"
  address       = "10.20.0.9"
  engine        = "postgres"
  tls_mode      = "require"
  database_name = "orders"
  tags          = { env = %q }
}
resource "zanskar_target" "wiki" {
  name         = "acc-wiki"
  app_upstream = "https://wiki.example.internal"
  tags         = { app = "yes" }
}
resource "zanskar_target" "held" {
  name             = "acc-held"
  app_upstream     = "https://held.example.internal"
  app_dependencies = "origins"
}
`, gw.cred, env, env)
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{Config: cfg("staging"), Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("zanskar_target.web", "tags.env", "staging"),
				resource.TestCheckResourceAttrPair("zanskar_target.web", "credentials.ssh", "data.zanskar_credential.linux", "id"),
				resource.TestCheckResourceAttr("zanskar_target.web", "status", "active"),
				resource.TestCheckResourceAttr("zanskar_target.db", "engine", "postgres"),
				resource.TestCheckResourceAttr("zanskar_target.db", "tls_mode", "require"),
				resource.TestCheckResourceAttr("zanskar_target.wiki", "app_upstream", "https://wiki.example.internal"),
				// The gateway's default, and the word set (2026-11-03).
				resource.TestCheckResourceAttr("zanskar_target.wiki", "app_dependencies", "public"),
				resource.TestCheckResourceAttr("zanskar_target.held", "app_dependencies", "origins"),
			)},
			// A change of tags is an update in place, keeping the target.
			{Config: cfg("prod"), Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("zanskar_target.web", "tags.env", "prod"),
				resource.TestCheckResourceAttr("zanskar_target.db", "tags.env", "prod"),
			)},
			{ResourceName: "zanskar_target.web", ImportState: true, ImportStateVerify: true},
		},
	})
}

func TestAccPolicy(t *testing.T) {
	url, token := gateway(t)
	cfg := func(clipboard bool, idle int) string {
		return providerBlock(url, token) + fmt.Sprintf(`
resource "zanskar_group" "dba" {
  name = "acc-dba"
}
resource "zanskar_target" "db" {
  name     = "acc-pol-db"
  address  = "10.30.0.9"
  engine   = "postgres"
  tls_mode = "require"
  tags     = { env = "prod" }
}
resource "zanskar_target" "box" {
  name      = "acc-pol-box"
  address   = "10.30.0.5"
  os_family = "linux"
  tags      = { env = "prod" }
}
resource "zanskar_access_policy" "prod" {
  name        = "acc-prod"
  description = "production by request"
  subjects    = [{ kind = "group", id = zanskar_group.dba.id }]
  grants = [
    {
      kind    = "database"
      targets = [{ id = zanskar_target.db.id, protocols = ["database"] }]
      access  = "approval"
      max_session_minutes = 60
    },
    {
      kind            = "host"
      tags            = { match = { env = ["prod"] }, protocols = ["ssh"] }
      allow_clipboard = %t
      idle_timeout_minutes = %d
      time_windows = [{ days = ["mon", "tue", "wed", "thu", "fri"], from = "08:00", to = "20:00", tz = "Europe/Berlin" }]
    },
  ]
}
`, clipboard, idle)
	}
	var firstGrant string
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{Config: cfg(false, 15), Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("zanskar_access_policy.prod", "grants.#", "2"),
				resource.TestCheckResourceAttr("zanskar_access_policy.prod", "grants.0.access", "approval"),
				resource.TestCheckResourceAttr("zanskar_access_policy.prod", "grants.0.max_session_minutes", "60"),
				resource.TestCheckResourceAttr("zanskar_access_policy.prod", "grants.1.time_windows.0.tz", "Europe/Berlin"),
				resource.TestCheckResourceAttr("zanskar_access_policy.prod", "grants.1.require_mfa", "true"),
				resource.TestCheckResourceAttr("zanskar_access_policy.prod", "enabled", "true"),
				func(s *terraform.State) error {
					firstGrant = s.RootModule().Resources["zanskar_access_policy.prod"].Primary.Attributes["grants.0.id"]
					if firstGrant == "" {
						return fmt.Errorf("the grant has no id")
					}
					return nil
				},
			)},
			// The clipboard on, a longer idle: the same policy, its grants
			// keeping their ids.
			{Config: cfg(true, 30), Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("zanskar_access_policy.prod", "grants.1.allow_clipboard", "true"),
				resource.TestCheckResourceAttr("zanskar_access_policy.prod", "grants.1.idle_timeout_minutes", "30"),
				func(s *terraform.State) error {
					if got := s.RootModule().Resources["zanskar_access_policy.prod"].Primary.Attributes["grants.0.id"]; got != firstGrant {
						return fmt.Errorf("the grant's id changed: %s, was %s", got, firstGrant)
					}
					return nil
				},
			)},
			{ResourceName: "zanskar_access_policy.prod", ImportState: true, ImportStateVerify: true},
		},
	})
}

// Refused by the gateway, the provider says why: a token that does not
// stand, and a policy the gateway will not take.
func TestAccRefusals(t *testing.T) {
	url, token := gateway(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config:      providerBlock(url, "zapi_notarealtoken") + `resource "zanskar_group" "x" { name = "acc-x" }`,
				ExpectError: regexpMust(`did not accept the token`),
			},
			{
				Config: providerBlock(url, token) + `
resource "zanskar_group" "auditors" {
  name = "acc-refusal-group"
}
resource "zanskar_access_policy" "bad" {
  name     = "acc-bad"
  subjects = [{ kind = "group", id = zanskar_group.auditors.id }]
  grants   = [{ kind = "host", allow_devtools = true, tags = { match = { env = ["prod"] }, protocols = ["ssh"] } }]
}`,
				ExpectError: regexpMust(`developer tools are for\s+application\s+grants only`),
			},
		},
	})
}

// A change made in the console shows as drift on the next plan, and an
// object deleted there is planned again (ADR 0044).
func TestAccDrift(t *testing.T) {
	url, token := gateway(t)
	c, err := NewClient(url, token, "", "test")
	if err != nil {
		t.Fatal(err)
	}
	cfg := providerBlock(url, token) + `
resource "zanskar_target" "drift" {
  name      = "acc-drift"
  address   = "10.40.0.5"
  os_family = "linux"
  tags      = { env = "prod" }
}
resource "zanskar_group" "drift" {
  name = "acc-drift-group"
}`
	var targetID, groupID string
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{Config: cfg, Check: func(s *terraform.State) error {
				targetID = s.RootModule().Resources["zanskar_target.drift"].Primary.ID
				groupID = s.RootModule().Resources["zanskar_group.drift"].Primary.ID
				return nil
			}},
			{
				// Someone retags it in the console.
				PreConfig: func() {
					ctx := context.Background()
					var cur apiTarget
					if err := c.do(ctx, http.MethodGet, "/targets/"+targetID, nil, &cur); err != nil {
						t.Fatal(err)
					}
					w := cur.write()
					w.Tags = map[string]string{"env": "dev"}
					if err := c.do(ctx, http.MethodPut, "/targets/"+targetID, w, nil); err != nil {
						t.Fatal(err)
					}
				},
				Config: cfg, PlanOnly: true, ExpectNonEmptyPlan: true,
			},
			// Applied, the configuration wins again.
			{Config: cfg, Check: resource.TestCheckResourceAttr("zanskar_target.drift", "tags.env", "prod")},
			{
				// Someone deletes the group in the console: planned again.
				PreConfig: func() {
					if err := c.do(context.Background(), http.MethodDelete, "/groups/"+groupID, nil, nil); err != nil {
						t.Fatal(err)
					}
				},
				Config: cfg, PlanOnly: true, ExpectNonEmptyPlan: true,
			},
			{Config: cfg, Check: resource.TestCheckResourceAttrWith("zanskar_group.drift", "id", func(v string) error {
				if v == groupID {
					return fmt.Errorf("the group was not made again")
				}
				return nil
			})},
		},
	})
}
