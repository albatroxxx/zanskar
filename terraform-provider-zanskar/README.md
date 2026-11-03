# Terraform provider for Zanskar

Manages a Zanskar gateway's groups, targets (hosts, databases, applications) and access
policies as code, over the gateway's configuration API, signed in with an administrator's
API token (ADR 0044). Credentials stay in the gateway's vault: a target names one by id,
looked up by name, so no secret is in a plan or a state.

## Sign in

In the console, *Settings › API tokens*, make a token (it asks for a code from your
authenticator) and keep it as you would a password. The token is you, on the configuration
API only, until it lapses or is revoked.

```sh
export ZANSKAR_URL=https://zanskar.example.com
export ZANSKAR_TOKEN=zapi_...
```

## Install from this repository

The provider is not on the Terraform Registry yet. Build it and point Terraform at it:

```sh
cd terraform-provider-zanskar
go build -o ~/.terraform.d/zanskar/terraform-provider-zanskar .
cat >> ~/.terraformrc <<'EOF'
provider_installation {
  dev_overrides {
    "albatroxxx/zanskar" = "/home/YOU/.terraform.d/zanskar"
  }
  direct {}
}
EOF
```

With `dev_overrides`, skip `terraform init` for this provider; `terraform plan` warns that
the override is in use.

## Example

```hcl
terraform {
  required_providers {
    zanskar = { source = "albatroxxx/zanskar" }
  }
}

provider "zanskar" {}  # ZANSKAR_URL and ZANSKAR_TOKEN

data "zanskar_credential" "linux" {
  name = "linux-svc"            # made in the console's vault
}

data "zanskar_group" "dba" {
  name = "dba"                  # brought by the identity provider
}

resource "zanskar_target" "web" {
  name        = "web-1"
  address     = "10.0.0.5"
  os_family   = "linux"
  tags        = { env = "prod", tier = "web" }
  credentials = { ssh = data.zanskar_credential.linux.id }
}

resource "zanskar_target" "orders" {
  name          = "orders-db"
  address       = "db.internal"
  engine        = "postgres"
  tls_mode      = "require"
  database_name = "orders"
  tags          = { env = "prod" }
}

resource "zanskar_access_policy" "prod" {
  name     = "prod"
  subjects = [{ kind = "group", id = data.zanskar_group.dba.id }]
  grants = [
    {
      kind    = "database"
      targets = [{ id = zanskar_target.orders.id, protocols = ["database"] }]
      access  = "approval"
      max_session_minutes = 60
    },
    {
      kind         = "host"
      tags         = { match = { env = ["prod"] }, protocols = ["ssh"] }
      time_windows = [{ days = ["mon", "tue", "wed", "thu", "fri"], from = "08:00", to = "20:00", tz = "Europe/Berlin" }]
    },
  ]
}
```

## What it manages

| Type | What |
|---|---|
| `zanskar_group` | A group's name and description. Members come from the identity provider or the console. |
| `zanskar_target` | A host (`os_family`, `ports`), a database (`engine`, `tls_mode`, `database_name`, `tls_ca`) or an application (`app_upstream`, `app_endpoints`, `app_dependencies`), with `tags`, `credentials` (ids by protocol), `notes`, `status`, `retention_days`. `capabilities` and `host_key_status` are read only: probing and trusting a host key stay a person's acts in the console. |
| `zanskar_access_policy` | `subjects` (groups and users by id) and `grants`, each with targets by id or by tag, `access` (standing or approval), `sign_in`, `require_mfa`, the clipboard, file transfer and developer tools switches, `idle_timeout_minutes`, `max_session_minutes`, `time_windows` and `retention_days`. A grant keeps its id across updates. Access reviews stay in the console. |
| `data.zanskar_credential` | A vaulted credential's id, by name. |
| `data.zanskar_group` | A group's id, by name. |

Everything imports by id: `terraform import zanskar_target.web <id>`. A change made in the
console shows as drift on the next plan; an object deleted there is planned again.

## Tests

`go test ./...` runs the unit tests. `TF_ACC=1 go test ./internal/provider/` builds the gateway
from this repository, starts it on SQLite in a temporary directory, makes a token through its
API, and runs Terraform against it: it needs `terraform` and a Go toolchain.
