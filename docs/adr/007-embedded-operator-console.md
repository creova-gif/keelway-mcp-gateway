# ADR-007: Embedded Zero-Dependency Operator Console (`GET /ui`)
- **Status:** Accepted
- **Owner:** Justin Mafie

## Context
With Milestone 2 observability endpoints (`GET /events`, `GET /p10/pending`, `POST /p10/resolve`, `GET /metrics`) in place, operators still lacked a built-in, zero-setup interface to monitor live gateway decisions, inspect metric counters, and resolve P-10 human-in-the-loop approval gates without deploying a separate frontend stack or exposing external CDN dependencies.

Because the Operator Console renders untrusted agent/tool metadata (server aliases, tool names, principal IDs, error reasons) and handles privileged operator bearer tokens used to resolve P-10 gates, it must be hardened against XSS, clickjacking, MIME-sniffing, token persistence leakage, and unauthenticated EventSource limitations.

## Decision
1. **Zero-Dependency Embedded SPA (`GET /ui` via `include_str!`):**
   - Serve a self-contained single-page HTML/CSS/JS Operator Console at `GET /ui` embedded directly into the gateway binary at compile time via `include_str!`.
   - Avoid external JS/CSS frameworks, CDNs, or separate build toolchains so the single-binary deployment model remains intact and air-gapped environments work out of the box.
2. **Strict Response Security Headers:**
   - Return `GET /ui` responses with hardened security headers:
     - `Content-Security-Policy` restricting script/style/connect origins to `'self'` (and inline/self policy appropriate for the embedded bundle without external network loads) and disallowing framing (`frame-ancestors 'none'`).
     - `X-Frame-Options: DENY` to prevent clickjacking.
     - `X-Content-Type-Options: nosniff` to prevent MIME-type sniffing.
     - `Cache-Control: no-store` so operator console HTML is never cached by intermediaries or browsers.
3. **`sessionStorage`-Only Token Handling:**
   - Store the operator bearer token exclusively in browser `sessionStorage` (never `localStorage`, cookies, or URL query parameters) so credentials are scoped to the active browser tab session and cleared when the tab closes.
4. **Authenticated `fetch` + `ReadableStream` SSE Consumption:**
   - Consume `GET /events` using `fetch()` with an explicit `Authorization: Bearer ...` header and `ReadableStream` line/frame parsing rather than the browser `EventSource` API, because native `EventSource` cannot send custom `Authorization` headers and would otherwise require passing tokens in query strings.
5. **`textContent`-Only XSS-Safe DOM Rendering:**
   - Render all dynamic fields from `/events`, `/p10/pending`, and `/metrics` exclusively via `textContent` and programmatic DOM node creation—never `innerHTML`, `outerHTML`, or `insertAdjacentHTML`—eliminating DOM-based XSS from tool names, principal identifiers, or upstream error payloads.

## Alternatives Considered
- **Separate Node/React frontend bundle or external CDN assets:** Rejected because it breaks single-binary zero-dependency deployment, adds supply-chain surface area, and fails in air-gapped environments.
- **Native `EventSource` with query-string token (`?token=...`):** Rejected because bearer tokens in URLs leak into browser history, proxy logs, and `Referer` headers.
- **`localStorage` token persistence:** Rejected because `localStorage` persists indefinitely across browser restarts and increases exposure if an XSS or shared-workstation risk occurs.

## Consequences & Failure Modes
- **UI changes require gateway rebuild:** Updating the embedded HTML/JS/CSS requires recompiling the gateway binary because assets are baked in via `include_str!`.
- **Single-tab token scope:** Using `sessionStorage` intentionally requires operators to re-enter their bearer token when opening a new tab or restarting the browser.
- **Stream reconnects:** Because `fetch` + `ReadableStream` does not auto-reconnect like `EventSource`, the console client must handle stream termination and reconnect/backoff explicitly when the gateway restarts or network connections drop.
