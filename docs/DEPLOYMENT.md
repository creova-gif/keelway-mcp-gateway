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
