# Three-Server Local Demo

Zero-setup demonstration of Keelway's offline security development lifecycle across three federated MCP servers (`github`, `database`, `filesystem`).

## Run Offline Policy Tests & Prompt-Injection Simulation

```bash
cargo run -p keelway-cli -- policy test \
  --config examples/three-server-demo/keelway.yaml \
  --tests examples/three-server-demo/policies/tests.yaml

cargo run -p keelway-cli -- attack simulate \
  --config examples/three-server-demo/keelway.yaml \
  --scenarios examples/three-server-demo/attacks/prompt-injection.yaml
```
