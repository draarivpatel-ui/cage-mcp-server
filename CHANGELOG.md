# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## [1.0.0] - 2026-11-27

### Added

- Initial public MCP stdio server with JSON-RPC 2.0 initialization, ping, tool discovery and tool invocation.
- Hybrid newline-delimited and strict `Content-Length` framing with bounded message sizes and malformed-input recovery.
- Ten AppSec tools backed by `sentinel-lint`, `pathcage`, `headersafe`, `redirectcage`, `envcage`, `cookiecage`, `zipcage`, `logcage`, `corscage` and `jsoncage`.
- Prototype-pollution rejection before JSON-RPC object use.
- Secret-minimizing output for dotenv and cookie audits.
- End-to-end stdio tests, adversarial framing tests, tool tests and repository hygiene tests.
- Ubuntu and Windows CI across Node.js 18, 20, 22 and 24.
- Official MCP Registry metadata in `server.json` and npm ownership metadata in `package.json`.
- Glama maintainer metadata in `glama.json`.
