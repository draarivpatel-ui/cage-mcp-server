# Contributing

## Ground rules

- Keep the runtime dependency set limited to the ten security packages already in `package.json`.
- Do not add a framework, logger, schema library or MCP SDK unless an issue explicitly approves it.
- Do not introduce shell execution, network access or caller-selected filesystem access.
- Preserve Node.js 18 compatibility.
- Keep stdout reserved for protocol messages. Diagnostics belong on stderr in development scripts, never in the server startup path.
- Do not commit credentials, tokens, local home-directory paths or real personal data.

## Setup

```sh
npm ci
npm test
npm run smoke
npm audit
```

Tests must pass on Ubuntu and Windows for Node.js 18, 20, 22 and 24.

## Making changes

1. Add or update a failing test that proves the behavior.
2. Make the smallest safe implementation change.
3. Run `npm test` and `npm run smoke`.
4. Check `npm audit` before submitting.
5. Keep public documentation synchronized with tool names, input bounds and security behavior.

## Code expectations

- Use strict input validation before calling a backing package.
- Keep inputs and outputs bounded. State the limit in the schema and enforce it in code.
- Return structured audit failures for hostile data. Reserve thrown errors for invalid arguments or unexpected operational failure.
- Never echo dotenv values or parsed cookie values.
- Do not mutate caller-owned objects.
- Avoid hidden global state. Temporary files must be cleaned up in `finally` blocks.

## Commit style

Write concise commits that explain why a change is needed. Do not add co-author trailers to repository history.
