# ADR-008: MCP Lifecycle and Resource/Prompt Governance
- **Status:** Accepted
- **Owner:** Justin Mafie

## Context
Standard Model Context Protocol (MCP) clients (such as Claude Desktop, Cursor, and IDE extensions) issue lifecycle JSON-RPC methods (`initialize`, `notifications/initialized`, `ping`) and capability queries (`resources/list`, `resources/read`, `prompts/list`, `prompts/get`) during normal session operation. Previously, the gateway only handled `initialize`, `tools/list`, and `tools/call`, returning `-32601 method not found` for `ping`, `notifications/initialized`, resources, and prompts, and advertising only `{"tools": {}}` in `initialize`.

Furthermore, `resources/read` and `prompts/get` fetch data from upstream MCP servers and therefore carry the same security risks as `tools/call`: unauthorized data access, secret leakage in upstream responses, oversized payloads, and missing audit provenance.

## Decision
1. **MCP Lifecycle & Discovery Support:**
   - Advertise `"capabilities": { "tools": {}, "resources": {}, "prompts": {} }` in the `initialize` response.
   - Handle `ping` by returning `{"jsonrpc": "2.0", "id": id, "result": {}}`.
   - Handle `notifications/initialized` (and any JSON-RPC notification without `"id"`) per JSON-RPC 2.0 / MCP Streamable HTTP: return `202 Accepted` with an empty body over HTTP and emit no response over stdio (if an explicit `"id"` is provided, return `{"jsonrpc": "2.0", "id": id, "result": {}}`).
   - Handle `resources/list` and `prompts/list` cleanly by returning empty lists (`{"resources": []}` and `{"prompts": []}`).
2. **Cedar Schema & `PolicyEngine::evaluate_action`:**
   - Extend the in-memory Cedar schema in `policy.rs` with `action "read_resource"` and `action "get_prompt"` (both applying to `principal: [Agent]`, `resource: [Tool]`, with `context.arg_checks`), while keeping `list_tool` and `call_tool` intact.
   - Introduce `PolicyEngine::evaluate_action(&self, principal: &Principal, action_name: &str, call: &ToolCall)` and delegate `PolicyEngine::evaluate` to `evaluate_action(principal, "call_tool", tool_call)`.
3. **Governed `resources/read` and `prompts/get` Dispatch:**
   - Resolve target `(server, uri)` for `resources/read` (from `params.server` + `params.uri`, or by parsing `<server>://<path>` from `params.uri`) and `(server, name)` for `prompts/get` (from `params.server` + `params.name`).
   - Enforce Cedar default-deny (`read_resource` / `get_prompt`), record fail-closed hash-chained audit tape receipts with `trace_id` provenance, enforce `max_request_bytes` and `max_response_bytes`, scrub upstream responses through `SecretScrubber`, and forward via a shared `UpstreamDriver::call_method` helper reused by `call_tool` so transport logic is never duplicated.

## Alternatives Considered
- **Passthrough without Cedar governance for resources/prompts:** Rejected because `resources/read` and `prompts/get` can expose sensitive files, credentials, or prompt templates from upstream servers, violating default-deny guarantees.
- **Separate transport implementation for resources/prompts:** Rejected because duplicating stdio/HTTP framing and streaming `SecretScrubber` logic increases maintenance risk; extracting `UpstreamDriver::call_method` keeps all transports uniform.

## Consequences & Failure Modes
- **Strict default-deny for resources and prompts:** Existing policies that only permit `call_tool` will deny `resources/read` and `prompts/get` until explicit `Action::"read_resource"` / `Action::"get_prompt"` rules are added.
- **Broad `permit` rules apply to all governed actions:** A Cedar rule such as `permit(principal, action, resource);` without `action == Action::"call_tool"` also matches `Action::"read_resource"` and `Action::"get_prompt"`. Scope `permit` rules explicitly to the intended `Action::"..."` when least-privilege separation between tools, resources, and prompts is required.
- **Empty list responses:** `resources/list` and `prompts/list` return empty lists rather than aggregating upstream resource/prompt catalogs; clients must address resources/prompts by explicit `(server, uri)` / `<server>://<path>` or `(server, name)`.
- **Invalid params fail fast:** Missing `uri` or `server` on `resources/read` / `prompts/get` returns JSON-RPC `-32602` before policy evaluation or upstream dispatch.
