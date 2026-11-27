# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |

Security fixes land on `main` and are released as a patch version. There are no
long lived release branches.

## Reporting a vulnerability

Report suspected vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/draarivpatel-ui/cage-mcp-server/security/advisories/new).

Please do not open a public issue, a public pull request or a discussion thread
with reproduction steps. If advisory access is unavailable, open only a minimal
public issue saying that a security report needs a private channel. Do not
include exploit details, proof-of-concept input, sensitive output, private files
or live credentials in that issue.

Please include:

- the package version and Node.js version
- whether the input used newline-delimited or `Content-Length` framing
- a minimal input that reproduces the behavior
- the expected security boundary
- whether the issue causes process termination, memory growth, unintended
  filesystem access, command execution, secret disclosure or incorrect audit
  output

Never include a real secret in a report. Rotate any credential used during
research before sending only its shape or a redacted example.

## Response and coordinated disclosure

- Reports are acknowledged within 48 hours.
- An initial assessment, including whether the report is in scope, is sent
  within 7 calendar days.
- A fix or mitigation plan for confirmed issues is developed as soon as
  practical. Process crashes, boundary escapes and secret disclosure are
  treated as urgent.
- Public disclosure is coordinated with the reporter. The default disclosure
  window is up to 90 days from acknowledgment, with earlier disclosure when a
  fix is available or a jointly agreed extension when more work is required.

Credit is offered in the advisory unless you ask to stay anonymous. We do not
operate a paid bounty.

## Security boundaries

The server is designed around these boundaries:

1. Tool input must never be executed or passed to a shell.
2. Tool input must never select arbitrary files for reading or writing.
3. ZIP input must be inspected in memory and never extracted by this server.
4. The `lint_security_code` snippet may be written only to a fresh temporary
   directory, scanned as data and deleted before return.
5. Dotenv values, parsed Cookie values and Set-Cookie audit values must not be
   echoed in structured output.
6. Malformed or hostile input must not crash the process or create unbounded
   memory growth.
7. Prototype-pollution keys must not be copied, merged or treated as ordinary
   configuration keys.

A report that crosses one of these boundaries is in scope. A disagreement about
whether a static finding is high, medium or low severity is generally not a
vulnerability, but concrete false-negative evidence is welcome.

## Safe harbor

Good faith research on your own systems and on this project's own code is
welcome. We will not pursue legal action for research that follows this policy,
avoids privacy violations and does not degrade service for other users.

## Hardening notes for integrators

- Run the server with the least privilege available to the MCP host.
- Do not place credentials in MCP command-line arguments because command lines
  are often visible to local process inspection.
- Treat tool output as untrusted data. It is structured JSON, not instructions
  to execute.
- Keep the exact package version pinned in host configuration.
