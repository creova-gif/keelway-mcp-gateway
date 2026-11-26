# Deployment Guide

This guide covers building and running Keelway MCP Gateway in containers, operating the Docker Compose observability stack, configuring Kubernetes health probes, and managing keys and pre-flight checks.

## Container Build and Run

The repository includes a multi-stage [Dockerfile](file:///Users/justinmafie/Documents/antigravity/keelway-mcp-gateway/Dockerfile) and [.dockerignore](file:///Users/justinmafie/Documents/antigravity/keelway-mcp-gateway/.dockerignore):

- **Builder stage (`rust:1-bookworm`):** Pre-caches workspace dependencies and compiles the release `keelway` binary with `--locked`.
- **Runtime stage (`debian:bookworm-slim`):** Installs `ca-certificates`, creates a non-root `keelway` system user, exposes port `8080`, sets `KEELWAY_BIND_ADDR=0.0.0.0:8080`, and runs `keelway gateway up --config /etc/keelway/keelway.yaml`.

Build the image from the repository root:

```sh
docker build -t keelway-mcp-gateway:latest .
```

Run the container with a read-only root filesystem, a `/tmp` tmpfs mount, and your `keelway.yaml` mounted at `/etc/keelway/keelway.yaml`:

```sh
docker run --rm -d \
  --name keelway \
  -p 8080:8080 \
  -e KEELWAY_BIND_ADDR=0.0.0.0:8080 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -v "$(pwd)/keelway.yaml:/etc/keelway/keelway.yaml:ro" \
  keelway-mcp-gateway:latest
```

> **Note:** Because the container runs as `USER keelway`, mounted configuration files, policy files, signing keys, and any writable tape directory must be readable (and writable for tape output) by the `keelway` user or group.

## `KEELWAY_BIND_ADDR`

`KEELWAY_BIND_ADDR` overrides the `bind_addr` setting in `keelway.yaml` when set to a non-empty value.

- In [Dockerfile](file:///Users/justinmafie/Documents/antigravity/keelway-mcp-gateway/Dockerfile), `KEELWAY_BIND_ADDR` defaults to `0.0.0.0:8080` so the gateway listens on all container interfaces.
- Override it at runtime to bind a different interface or port (for example, `KEELWAY_BIND_ADDR=127.0.0.1:9000`).

## Docker Compose Observability Stack

Reference manifests are provided in [deploy/compose.yaml](file:///Users/justinmafie/Documents/antigravity/keelway-mcp-gateway/deploy/compose.yaml) and [deploy/prometheus.yml](file:///Users/justinmafie/Documents/antigravity/keelway-mcp-gateway/deploy/prometheus.yml).

The stack starts:

1. **`keelway`**: Built from the repository root `Dockerfile`, bound to `0.0.0.0:8080`, running with `read_only: true`, `/tmp` tmpfs, dropped capabilities, and a `/healthz` healthcheck.
2. **`prometheus`**: Mounts `deploy/prometheus.yml` and scrapes `keelway:8080/metrics` every `15s`, waiting until `keelway` is healthy.

Place your `keelway.yaml` in `deploy/keelway.yaml` (or update the volume mount in `deploy/compose.yaml`) and start the stack:

```sh
docker compose -f deploy/compose.yaml up -d --build
```

- Gateway HTTP endpoint: `http://localhost:8080/mcp`
- Prometheus UI: `http://localhost:9090`

## Prometheus Alerting (`deploy/alerts.yml`)

Reference Prometheus alerting rules are provided in [deploy/alerts.yml](file:///Users/justinmafie/Documents/antigravity/keelway-mcp-gateway/deploy/alerts.yml) under the `keelway_gateway` rule group:

- **`KeelwayUpstreamCircuitOpen`**: Fires when `keelway_circuits_open > 0` for `1m` (`severity: critical`).
- **`KeelwayUpstreamErrorsHigh`**: Fires when `rate(keelway_upstream_errors_total[5m]) > 0.1` for `2m` (`severity: warning`).
- **`KeelwayP10QueueBacklog`**: Fires when `keelway_p10_pending > 10` for `5m` (`severity: warning`).
- **`KeelwayPolicyDenySpike`**: Fires when `rate(keelway_calls_total{outcome="denied_policy"}[5m]) > 1` for `2m` (`severity: warning`).

To enable these rules in Prometheus, mount `deploy/alerts.yml` into your Prometheus container and reference it under `rule_files` in `prometheus.yml`:

```yaml
rule_files:
  - /etc/prometheus/alerts.yml
```

## Kubernetes Deployment (`deploy/k8s/`)

Hardened Kubernetes reference manifests are provided in [deploy/k8s/deployment.yaml](file:///Users/justinmafie/Documents/antigravity/keelway-mcp-gateway/deploy/k8s/deployment.yaml) and [deploy/k8s/service.yaml](file:///Users/justinmafie/Documents/antigravity/keelway-mcp-gateway/deploy/k8s/service.yaml):

- **Deployment (`keelway-gateway`)**:
  - Security context: `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]`, and `seccompProfile.type: RuntimeDefault`.
  - Sets `KEELWAY_BIND_ADDR: "0.0.0.0:8080"` and `terminationGracePeriodSeconds: 30`.
  - Mounts ConfigMap `keelway-config` (read-only) at `/etc/keelway`, PVC `keelway-data` at `/var/lib/keelway` for audit tapes, and a memory-backed `emptyDir` at `/tmp`.
  - Configures `/healthz` liveness and `/readyz` readiness probes.
- **Service (`keelway-gateway`)**:
  - `ClusterIP` on port `8080` with `prometheus.io/scrape: "true"`, `prometheus.io/path: "/metrics"`, and `prometheus.io/port: "8080"` annotations.

Create the prerequisite `keelway-config` ConfigMap and `keelway-data` PVC in your target namespace, then apply the manifests:

```sh
kubectl apply -f deploy/k8s/
```

## Kubernetes Liveness and Readiness Probes

Keelway exposes separate liveness and readiness endpoints:

- **`GET /healthz`** (Liveness): Returns `200 OK` with `{"status": "ok"}` while the HTTP server is responsive.
- **`GET /readyz`** (Readiness): Inspects upstream circuit breaker state. Returns `200 OK` with `{"ready": true, "open_circuits": 0}` when all upstream circuits are closed/half-open, or `503 Service Unavailable` with `{"ready": false, "open_circuits": <count>}` when one or more upstream circuits are `Open`.

Example Kubernetes probe configuration:

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 15
  timeoutSeconds: 3
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /readyz
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
  timeoutSeconds: 3
  failureThreshold: 3
```

## Signing Key Generation (`keelway keygen`)

Generate a random 32-byte Ed25519 signing key for audit tape provenance:

```sh
# Print seed_hex, key_id, and verifying_key to stdout
keelway keygen

# Write the key to a file (0600 permissions on Unix) and print the config hint
keelway keygen --output /etc/keelway/signing.key
```

Reference the generated key in `keelway.yaml` using `signing_key_ref: "secret://file/etc/keelway/signing.key"` (adjusting the path as appropriate), and verify recorded audit tapes offline with:

```sh
keelway trace inspect --tape keelway-tape.jsonl --public-key <verifying_key>
```

## Pre-Flight Diagnostics (`keelway doctor`)

Run `keelway doctor` before deploying or promoting a configuration change to validate configuration parsing, policy loading, signing key resolution, and auth/runtime readiness offline:

```sh
keelway doctor --config /etc/keelway/keelway.yaml
```

The command prints a per-check summary (`PASS`, `SKIP`, or `FAIL`) and exits with a non-zero status code if any check fails.
