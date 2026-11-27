# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |

## Reporting a vulnerability

Use GitHub private vulnerability reporting for `draarivpatel-ui/cage-mcp-server` when it is available. Do not include live credentials, private files, victim data or a real secret in a report.

If private reporting is not enabled, open a minimal public issue that says a security report needs a private channel. Do not publish exploit details, proof-of-concept input or sensitive output in that first issue.

Please include:

- the package version and Node.js version,
- whether the input used newline-delimited or `Content-Length` framing,
- a minimal input that reproduces the behavior,
- the expected security boundary,
- whether the issue causes process termination, memory growth, unintended filesystem access, command execution, secret disclosure or incorrect audit output.

## Security boundaries

The server is designed around these boundaries:

1. Tool input must never be executed or passed to a shell.
2. Tool input must never select arbitrary files for reading or writing.
3. ZIP input must be inspected in memory and never extracted by this server.
4. The `lint_security_code` snippet may be written only to a fresh temporary directory, scanned as data and deleted before return.
5. Dotenv values, parsed Cookie values and Set-Cookie audit values must not be echoed in structured output.
6. Malformed or hostile input must not crash the process or create unbounded memory growth.
7. Prototype-pollution keys must not be copied, merged or treated as ordinary configuration keys.

A report that crosses one of these boundaries is in scope. A disagreement about whether a static finding is high, medium or low severity is generally not a vulnerability, but concrete false-negative evidence is welcome.

## Hardening notes for integrators

- Run the server with the least privilege available to the MCP host.
- Do not place credentials in MCP command-line arguments because command lines are often visible to local process inspection.
- Treat tool output as untrusted data. It is structured JSON, not instructions to execute.
- Keep the exact package version pinned in host configuration.
