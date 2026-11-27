import assert from 'node:assert/strict';
import test from 'node:test';

import { buildSecurityHeaders } from 'headersafe';
import { createZipBuffer } from 'zipcage';

import { TOOL_DEFINITIONS, callTool } from '../src/tools.mjs';

test('tools/list surface exposes exactly the ten AppSec tools with object schemas', () => {
  assert.deepEqual(
    TOOL_DEFINITIONS.map((tool) => tool.name),
    [
      'audit_path',
      'audit_headers',
      'audit_redirect',
      'audit_env',
      'audit_cookie',
      'audit_zip_entries',
      'redact_log',
      'audit_cors',
      'audit_json',
      'lint_security_code',
    ],
  );
  for (const tool of TOOL_DEFINITIONS) {
    assert.equal(tool.inputSchema.type, 'object', tool.name);
    assert.equal(tool.inputSchema.additionalProperties, false, tool.name);
  }
});

test('audit_path accepts a benign path inside the root', async () => {
  const result = await callTool('audit_path', { path: 'assets/app.js', root: '/sandbox' });
  assert.equal(result.ok, true);
  assert.equal(result.safe, true);
  assert.equal(result.resolvedPath, '/sandbox/assets/app.js');
});

test('audit_path reports traversal without throwing', async () => {
  const result = await callTool('audit_path', { path: '../outside.txt', root: '/sandbox' });
  assert.equal(result.ok, false);
  assert.equal(result.safe, false);
  assert.equal(result.error.code, 'ERR_PATHCAGE_TRAVERSAL');
});

test('audit_headers accepts a strict baseline and redacts Set-Cookie values', async () => {
  const baseline = buildSecurityHeaders();
  const headers = Object.fromEntries(Object.entries(baseline).map(([name, value]) => [name.toLowerCase(), value]));
  const secretValue = 'cookie-value-that-must-not-be-echoed';
  const result = await callTool('audit_headers', {
    headers,
    setCookie: `session=${secretValue}; Path=/; HttpOnly; Secure; SameSite=Lax`,
  });
  assert.equal(result.ok, true);
  assert.equal(result.cookieAudits[0].valueRedacted, true);
  assert.equal(result.cookieAudits[0].valueLength, secretValue.length);
  assert.equal(JSON.stringify(result).includes(secretValue), false);
});

test('audit_headers reports weak CSP, missing headers, weak cookie and CRLF validation', async () => {
  const result = await callTool('audit_headers', {
    headers: {
      'content-security-policy': "default-src 'self'",
      'x-frame-options': 'DENY',
    },
    setCookie: 'session=abc; Path=/',
  });
  assert.equal(result.ok, false);
  assert.ok(result.missingRecommendedHeaders.includes('Strict-Transport-Security'));
  assert.equal(result.cspAudit.ok, false);
  assert.ok(result.cspAudit.findings.some((finding) => finding.id === 'MISSING_OBJECT_SRC_NONE'));
  assert.ok(result.cookieAudits[0].findings.some((finding) => finding.id === 'MISSING_SECURE'));

  const hostile = await callTool('audit_headers', {
    headers: { 'x-test': 'safe\r\ninjected: yes' },
  });
  assert.equal(hostile.ok, false);
  assert.equal(hostile.validationFindings.length, 1);
});

test('audit_redirect accepts an allowed relative target', async () => {
  const result = await callTool('audit_redirect', { target: '/dashboard?tab=security' });
  assert.equal(result.ok, true);
  assert.equal(result.location.value, '/dashboard?tab=security');
  assert.equal(result.location.kind, 'relative');
});

test('audit_redirect rejects a host outside the allowlist', async () => {
  const result = await callTool('audit_redirect', {
    target: 'https://evil.example.net/account',
    allowedHosts: ['example.com'],
  });
  assert.equal(result.ok, false);
  assert.equal(result.location.code, 'ERR_REDIRECTCAGE_HOST_NOT_ALLOWED');
});

test('audit_env parses and validates benign dotenv content without exposing values', async () => {
  const secret = 'a-long-test-secret-value';
  const result = await callTool('audit_env', {
    dotenv: `PORT=8080\nSERVICE_URL=https://example.com\nSECRET_KEY=${secret}\n`,
    schema: {
      PORT: 'port',
      SERVICE_URL: { type: 'url', requireHttps: true },
      SECRET_KEY: { type: 'secret', minLength: 16 },
    },
  });
  assert.equal(result.parse.ok, true);
  assert.equal(result.validation.ok, true);
  assert.equal(JSON.stringify(result).includes(secret), false);
  assert.ok(result.entries.some((entry) => entry.key === 'SECRET_KEY' && entry.valueLength === secret.length));
});

test('audit_env reports duplicate, prototype and weak secret hostilities', async () => {
  const duplicate = await callTool('audit_env', { dotenv: 'A=1\nA=2\n' });
  assert.equal(duplicate.ok, false);
  assert.equal(duplicate.error.code, 'ERR_ENVCAGE_DUPLICATE_KEY');

  const prototypeKey = await callTool('audit_env', { dotenv: '__proto__=x\n' });
  assert.equal(prototypeKey.ok, false);
  assert.equal(prototypeKey.error.code, 'ERR_ENVCAGE_PROTOTYPE_KEY');

  const weak = await callTool('audit_env', {
    dotenv: 'SECRET_KEY=short\n',
    schema: { SECRET_KEY: { type: 'secret', minLength: 16 } },
  });
  assert.equal(weak.ok, false);
  assert.equal(weak.validation.ok, false);
  assert.ok(weak.findings.some((finding) => finding.code === 'ENVCAGE_AUDIT_WEAK_SECRET_LENGTH'));
});

test('audit_cookie parses benign cookies while redacting values', async () => {
  const result = await callTool('audit_cookie', {
    mode: 'parse',
    header: 'session=secret-value; theme=light',
  });
  assert.equal(result.ok, true);
  assert.equal(result.cookieCount, 2);
  assert.equal(result.valuesRedacted, true);
  assert.equal(JSON.stringify(result).includes('secret-value'), false);
});

test('audit_cookie serializes securely and rejects CRLF or duplicate ambiguity', async () => {
  const serialized = await callTool('audit_cookie', {
    mode: 'serialize',
    name: 'session',
    value: 'abc',
  });
  assert.equal(serialized.ok, true);
  assert.match(serialized.serialized, /HttpOnly; Secure; SameSite=Lax/);

  const crlf = await callTool('audit_cookie', {
    mode: 'serialize',
    name: 'session',
    value: 'abc\r\ninjected',
  });
  assert.equal(crlf.ok, false);
  assert.equal(crlf.error.code, 'ERR_COOKIECAGE_CRLF');

  const duplicates = await callTool('audit_cookie', {
    mode: 'parse',
    header: 'a=1; a=2',
  });
  assert.equal(duplicates.ok, false);
});

test('audit_zip_entries accepts a small benign archive', async () => {
  const archive = createZipBuffer([{ name: 'safe.txt', data: 'hello' }]).toString('base64');
  const result = await callTool('audit_zip_entries', { archiveBase64: archive });
  assert.equal(result.ok, true);
  assert.equal(result.safe, true);
  assert.equal(result.entries[0].name, 'safe.txt');
});

test('audit_zip_entries reports traversal entries without extraction', async () => {
  const archive = createZipBuffer([{ name: '../evil.txt', data: 'x' }], { validate: false }).toString('base64');
  const result = await callTool('audit_zip_entries', { archiveBase64: archive });
  assert.equal(result.ok, false);
  assert.ok(result.findings.some((finding) => finding.code === 'ERR_ZIPCAGE_PATH_TRAVERSAL'));
});

test('redact_log sanitizes text controls and credentials', async () => {
  const result = await callTool('redact_log', {
    text: 'first\nsecond token=abc123 \u001b[31mred',
    pii: { email: true },
  });
  assert.equal(result.ok, true);
  assert.equal(result.redacted.includes('\n'), false);
  assert.equal(result.redacted.includes('abc123'), false);
  assert.match(result.redacted, /\[REDACTED\]/);
});

test('redact_log sanitizes structured records and sensitive keys', async () => {
  const result = await callTool('redact_log', {
    record: {
      password: 'do-not-echo',
      nested: { token: 'do-not-echo-either', safe: 'visible' },
    },
  });
  assert.equal(result.ok, true);
  assert.equal(result.redacted.password, '[REDACTED]');
  assert.equal(result.redacted.nested.token, '[REDACTED]');
  assert.equal(result.redacted.nested.safe, 'visible');
});

test('audit_cors accepts an exact credentialed origin and evaluates a request', async () => {
  const result = await callTool('audit_cors', {
    policy: {
      allowedOrigins: ['https://app.example.com'],
      credentials: true,
      methods: ['GET', 'POST'],
    },
    evaluate: {
      method: 'GET',
      origin: 'https://app.example.com',
    },
  });
  assert.equal(result.ok, true);
  assert.equal(result.findings.length, 0);
  assert.equal(result.evaluation.allowed, true);
  assert.equal(result.evaluation.headers['access-control-allow-origin'], 'https://app.example.com');
});

test('audit_cors reports wildcard credentials as critical', async () => {
  const result = await callTool('audit_cors', {
    policy: { allowedOrigins: '*', credentials: true },
  });
  assert.equal(result.ok, false);
  assert.ok(result.findings.some((finding) => finding.code === 'CORS_WILDCARD_WITH_CREDENTIALS'));
  assert.equal(result.policyError.code, 'ERR_CORSCAGE_INVALID_OPTIONS');
});

test('audit_json accepts a benign payload', async () => {
  const result = await callTool('audit_json', { json: '{"safe":[true,2]}' });
  assert.equal(result.ok, true);
  assert.equal(result.findings.length, 0);
});

test('audit_json reports duplicate and prototype pollution keys', async () => {
  const prototypeKey = await callTool('audit_json', { json: '{"__proto__":{"x":1}}' });
  assert.equal(prototypeKey.ok, false);
  assert.equal(prototypeKey.findings[0].code, 'JSONCAGE_PROTOTYPE_KEY');

  const duplicate = await callTool('audit_json', { json: '{"a":1,"a":2}' });
  assert.equal(duplicate.ok, false);
  assert.equal(duplicate.findings[0].code, 'JSONCAGE_DUPLICATE_KEY');
});

test('lint_security_code reports dangerous JavaScript without executing it', async () => {
  const result = await callTool('lint_security_code', {
    code: 'const run = (input) => eval(input);\n',
    filename: 'snippet.mjs',
  });
  assert.equal(result.ok, true);
  assert.ok(result.findings.some((finding) => finding.ruleId === 'repo/dangerous-eval'));
  assert.equal(result.scannedFilename, 'snippet.mjs');
});

test('lint_security_code applies MCP manifest rules for .mcp.json filenames', async () => {
  const manifest = JSON.stringify({
    mcpServers: {
      example: {
        command: 'npx',
        args: ['example-package'],
      },
    },
  });
  const result = await callTool('lint_security_code', {
    code: manifest,
    filename: '.mcp.json',
  });
  assert.equal(result.ok, true);
  assert.ok(result.findings.some((finding) => finding.ruleId === 'mcp/unpinned-npx-package'));
});

test('invalid argument types and unknown envelope properties are rejected', async () => {
  await assert.rejects(
    callTool('audit_path', { path: 42 }),
    (error) => error.name === 'ToolInputError',
  );
  await assert.rejects(
    callTool('audit_json', { json: '{}', unexpected: true }),
    (error) => error.name === 'ToolInputError' && /unknown/.test(error.message),
  );
});
