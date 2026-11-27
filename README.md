# cage-mcp-server

`cage-mcp-server` is an offline Model Context Protocol server that gives AI coding assistants deterministic application-security guardrails. It exposes ten bounded MCP tools backed directly by ten published npm security packages: `sentinel-lint`, `pathcage`, `headersafe`, `redirectcage`, `envcage`, `cookiecage`, `zipcage`, `logcage`, `corscage`, and `jsoncage`.

The server speaks JSON-RPC 2.0 over stdio. It supports the newline-delimited framing used by MCP stdio clients and strict `Content-Length` framing for harnesses that use that transport style.

## Security model

- **Offline and deterministic:** the server makes no network requests and does not depend on a model, a cloud API or a remote scanner.
- **No command execution:** tool input is never evaluated, passed to a shell or executed as source. `lint_security_code` writes a snippet only so `sentinel-lint` can scan it as data.
- **Tightly bounded:** JSON-RPC frames are limited to 2 MiB, header blocks to 8 KiB, and every tool applies stricter input limits before calling a security package.
- **Prototype-pollution resistant:** `__proto__`, `constructor` and `prototype` keys are rejected in the JSON-RPC envelope before arguments are used. JSON text supplied as a string can still be audited for those keys by `audit_json`.
- **Filesystem minimization:** the server never reads or writes caller-selected paths. The only filesystem write is a mode-0600 temporary source snippet in the operating-system temporary directory for `lint_security_code`; it is removed in a `finally` block before the tool returns. ZIP archives are inspected in memory and never extracted.
- **Secret minimization:** dotenv values are never returned. Parsed Cookie values are redacted. Set-Cookie audit values are redacted. Use `redact_log` before putting potentially sensitive log data into a model transcript.
- **Fail-closed framing:** malformed JSON, invalid UTF-8, duplicate length headers, unsupported headers, oversized frames and prototype-pollution keys produce bounded JSON-RPC errors rather than process crashes.
- **Static analysis limits:** findings are deterministic guardrails, not proof that an application is secure. They complement review, testing and runtime controls.

## Install and run

Node.js 18 or newer is required.

From a source checkout:

```sh
npm ci
npm test
npm run smoke
node bin/cage-mcp-server.mjs
```

The process intentionally writes no startup banner. MCP clients own stdin and stdout.

## MCP client configuration

The examples use the intended npm executable `cage-mcp-server@1.0.0`. Pinning the exact version prevents a future package release from being selected silently.

### Claude Code

CLI registration:

```sh
claude mcp add cage-security -- npx -y cage-mcp-server@1.0.0
```

Equivalent project-scoped `.mcp.json`:

```json
{
  "mcpServers": {
    "cage-security": {
      "command": "npx",
      "args": ["-y", "cage-mcp-server@1.0.0"]
    }
  }
}
```

### Codex CLI

CLI registration:

```sh
codex mcp add cage-security -- npx -y cage-mcp-server@1.0.0
```

Equivalent `~/.codex/config.toml` entry:

```toml
[mcp_servers.cage-security]
command = "npx"
args = ["-y", "cage-mcp-server@1.0.0"]
startup_timeout_sec = 10
tool_timeout_sec = 30
```

### Cursor

Add this server to the Cursor MCP configuration:

```json
{
  "mcpServers": {
    "cage-security": {
      "command": "npx",
      "args": ["-y", "cage-mcp-server@1.0.0"]
    }
  }
}
```

### Windsurf

Open the MCP config file from the Cascade MCP menu and add:

```json
{
  "mcpServers": {
    "cage-security": {
      "command": "npx",
      "args": ["-y", "cage-mcp-server@1.0.0"]
    }
  }
}
```

Refresh the MCP server list after saving.

## Tool reference

| MCP tool | Backing package | Purpose | Required input |
| --- | --- | --- | --- |
| `audit_path` | `pathcage` | Lexically resolve a path inside an absolute root and report traversal, encoded traversal and length violations. No filesystem access. | `path` |
| `audit_headers` | `headersafe` | Validate header names and values, audit CSP and Set-Cookie strings, and compare supplied headers with a strict baseline. | one of `headers`, `csp`, `setCookie` |
| `audit_redirect` | `redirectcage` | Evaluate relative or absolute redirect targets against explicit origin, host, protocol, query, fragment and blocked-path policy. | `target` |
| `audit_env` | `envcage` | Parse dotenv text without expansion or interpolation, optionally validate a schema, and report secret hygiene without returning values. | `dotenv` |
| `audit_cookie` | `cookiecage` | Parse Cookie headers with duplicate and encoding protection, or serialize a hardened Set-Cookie header. | `mode` plus mode fields |
| `audit_zip_entries` | `zipcage` | Inspect a small base64 ZIP archive in memory for traversal, polyglot structure, compression bombs, special files, encryption and metadata inconsistencies. | `archiveBase64` |
| `redact_log` | `logcage` | Sanitize line-forging controls and redact credentials, tokens, sensitive object keys and optional high-precision PII patterns. | exactly one of `text`, `record` |
| `audit_cors` | `corscage` | Lint a CORS policy and optionally evaluate a bounded request for origin, method, credential, preflight and private-network behavior. | none; `policy` recommended |
| `audit_json` | `jsoncage` | Inspect JSON text for duplicate keys, prototype-pollution keys, excess depth or size, unsafe numbers, Unicode hazards and NUL hazards. | `json` |
| `lint_security_code` | `sentinel-lint` | Scan one bounded source snippet for dangerous eval and HTML sinks, command-injection patterns, hardcoded credential shapes, insecure MCP configuration and risky GitHub Actions patterns. | `code` |

Every tool accepts a JSON object and returns both MCP text content and structured content. An unsafe audit result normally has `ok: false`; it is not a tool execution failure. `isError: true` is reserved for operational failures inside the tool.

## Example JSON-RPC exchange

Newline-delimited stdio:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"example-client","version":"1.0.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"audit_json","arguments":{"json":"{\"__proto__\":{\"x\":1}}"}}}
```

The final response has a structured result similar to:

```json
{
  "ok": false,
  "findings": [
    {
      "code": "JSONCAGE_PROTOTYPE_KEY",
      "message": "prototype pollution key rejected",
      "position": 1,
      "key": "__proto__"
    }
  ]
}
```

## Development

```sh
npm ci
npm test
npm run smoke
npm audit
```

The test suite uses only `node:test`. It covers direct behavior for all ten tools, newline-delimited and `Content-Length` stdio sessions, malformed JSON, oversized frames, prototype pollution, unknown methods, invalid arguments and repository hygiene.

Runtime dependencies are intentionally limited to the ten security packages. There are no other runtime or development npm dependencies.

## Repository layout

| Path | Purpose |
| --- | --- |
| `bin/cage-mcp-server.mjs` | Executable stdio entrypoint |
| `src/server.mjs` | JSON-RPC validation, hybrid framing, lifecycle and tool dispatch |
| `src/tools.mjs` | Tool schemas, strict input validation and package adapters |
| `src/validation.mjs` | Bounded validation helpers and prototype-key rejection |
| `test/` | Unit, integration, adversarial and hygiene tests |
| `scripts/smoke-mcp.mjs` | Live stdio smoke test used by CI |

## License

MIT. See [LICENSE](LICENSE).
