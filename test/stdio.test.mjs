import assert from 'node:assert/strict';
import test from 'node:test';

import {
  contentLengthInput,
  initializeMessage,
  ndjsonInput,
  parseContentLengthFrames,
  parseNdjson,
  runServerInput,
} from '../testkit/stdio.mjs';

test('stdio server handles newline-delimited initialize, initialized notification, ping and tools/list', async () => {
  const run = await runServerInput(ndjsonInput([
    initializeMessage(1),
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    { jsonrpc: '2.0', id: 2, method: 'ping' },
    { jsonrpc: '2.0', id: 3, method: 'tools/list' },
  ]));

  assert.equal(run.code, 0);
  assert.equal(run.stderr, '');
  const responses = parseNdjson(run.stdout);
  assert.deepEqual(responses.map((message) => message.id), [1, 2, 3]);
  assert.equal(responses[0].result.protocolVersion, '2025-11-25');
  assert.equal(responses[0].result.serverInfo.name, 'cage-mcp-server');
  assert.deepEqual(responses[1].result, {});
  assert.equal(responses[2].result.tools.length, 10);
  assert.ok(responses[2].result.tools.every((tool) => typeof tool.inputSchema === 'object'));
});

test('stdio server handles strict Content-Length framing and a live tool call', async () => {
  const run = await runServerInput(contentLengthInput([
    initializeMessage(1),
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    {
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: {
        name: 'audit_path',
        arguments: { path: 'safe/file.txt', root: '/sandbox' },
      },
    },
  ]));

  assert.equal(run.code, 0);
  assert.equal(run.stderr, '');
  assert.match(run.stdout, /^Content-Length: \d+\r\n\r\n/);
  const responses = parseContentLengthFrames(run.stdoutBuffer);
  assert.deepEqual(responses.map((message) => message.id), [1, 2]);
  assert.equal(responses[1].result.structuredContent.ok, true);
  assert.equal(responses[1].result.structuredContent.resolvedPath, '/sandbox/safe/file.txt');
  assert.equal(responses[1].result.isError, false);
});

test('initialize negotiates an older supported version and falls back for an unknown version', async () => {
  const older = initializeMessage(1);
  older.params.protocolVersion = '2025-06-18';
  const unknown = initializeMessage(2);
  unknown.params.protocolVersion = '1999-01-01';
  const run = await runServerInput(ndjsonInput([older, unknown]));
  assert.equal(run.code, 0);
  const responses = parseNdjson(run.stdout);
  assert.equal(responses[0].result.protocolVersion, '2025-06-18');
  assert.equal(responses[1].result.protocolVersion, '2025-11-25');
});

test('newline and Content-Length frames can be processed in one stdio session', async () => {
  const newline = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' }) + '\n';
  const framedBody = JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'ping' });
  const framed = `Content-Length: ${Buffer.byteLength(framedBody)}\r\n\r\n${framedBody}`;
  const run = await runServerInput(newline + framed);
  assert.equal(run.code, 0);
  assert.equal(run.stderr, '');
  const firstEnd = run.stdout.indexOf('\n') + 1;
  const first = JSON.parse(run.stdout.slice(0, firstEnd));
  assert.equal(first.id, 1);
  assert.equal(first.result && Object.keys(first.result).length, 0);
  const rest = run.stdoutBuffer.subarray(firstEnd);
  const responses = parseContentLengthFrames(rest);
  assert.equal(responses.length, 1);
  assert.equal(responses[0].id, 2);
});
