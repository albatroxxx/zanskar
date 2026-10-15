# 0031. Monitoring: current state in the console, time series through an exporter

Date: 2026-10-15

## Status

Proposed.

## Context

The admin dashboard now shows the gateway host's numbers right now — load, memory, the
volumes it writes, database session containers, guacd reachability — and the next goal is
monitoring the assets themselves: are targets reachable, are databases answering, is an
autoscaling pool degraded.

The tempting path is to grow the console into a small monitoring system: store samples,
draw charts, fire alerts. That path ends with Zanskar competing with Prometheus and
Grafana using a security gateway's database and an operator's trust, and doing all three
jobs worse.

## Decision (proposed)

**The console shows current state with thresholds. Time series, history, charts and
alerting belong to the operator's monitoring stack, fed by a Prometheus-format exporter.**

- **`GET /metrics`** serves the Prometheus text format: the gateway's own gauges (what
  `admin/system/metrics` shows, plus session counts by protocol and audit failure
  counters) and, once asset monitoring exists, one gauge set per target (reachable,
  latency, last-probe age). The endpoint is **authenticated** — a bearer token minted for
  the scraper, never the console session — because metrics names every target and its
  state: topology an open endpoint would leak.
- **Asset monitoring = scheduled probes, stored as current state only.** The prober that
  already answers "probe this host" on demand runs on a schedule (per-target opt-in, with
  a global default off), writing the latest result onto the target row — reachable,
  latency, checked-at — never a history table. The dashboard's inventory tiles and the
  Hosts table show that state; the exporter publishes it; Prometheus keeps the history.
- **Alerting is not Zanskar's job.** The console colours a number when it crosses a
  threshold; paging someone is the monitoring stack's. The one exception stays as is:
  audit-worthy events (host key changed, sync failures) already land in the audit log and
  its webhooks.
- Probe cadence is a security decision, not just a tuning knob: the gateway generating
  periodic connections to every enrolled machine changes its network signature and
  touches targets' logs. The default is therefore conservative (minutes, not seconds),
  per-target configurable, and every probe stays an audited `target.probe` only when an
  administrator triggers it by hand — scheduled probes are logged, not audited, so the
  chain is not flooded (the ADR 0029 line).

## Consequences

- Operators point their existing Prometheus/Grafana/Alertmanager at one authed endpoint
  and get history and paging without Zanskar storing a single sample.
- The console stays a glance: the dashboard's gateway card and the target tables gain
  "now" columns, nothing gains a chart.
- New pieces when built: the exporter endpoint with its token, the probe scheduler, a
  `last_probe` state on targets and ASG instances, and documentation for the scrape
  config.

## Alternatives considered

- **Samples in SQLite + charts in the console** — rejected: retention, compaction and
  query load in the gateway's own database, a worse Grafana, and a bigger attack surface.
- **Unauthenticated `/metrics` like most exporters** — rejected: the metric labels are a
  map of everything the gateway can reach.
- **Pushing to a webhook instead of an exporter** — rejected as the primary path: every
  stack can scrape Prometheus format; push formats multiply.
