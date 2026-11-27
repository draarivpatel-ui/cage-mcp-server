import assert from 'node:assert/strict';
import test from 'node:test';

import { HybridJsonRpcFramer, DEFAULT_MAX_MESSAGE_BYTES } from '../src/server.mjs';
import {
  initializeMessage,
  ndjsonInput,
  parseNdjson,
  runServerInput,
} from '../testkit/stdio.mjs';

test('malformed JSON returns a parse error and the server continues with later frames', async () => {
  const validPing = JSON.stringify({ jsonrpc: '2.0', id: 9, method: 'ping' });
  const run = await runServerInput(`{"jsonrpc":"2.0",broken\n${validPing}\n`);
  assert.equal(run.code, 0);
  assert.equal(run.stderr, '');
  const responses = parseNdjson(run.stdout);
  assert.equal(responses.length, 2);
  assert.equal(responses[0].id, null);
  assert.equal(responses[0].error.code, -32700);
  assert.equal(responses[1].id, 9);
  assert.deepEqual(responses[1].result, {});
});

test('prototype pollution keys in the JSON-RPC envelope are rejected before object use', async () => {
  const lines = [
    '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"audit_json","arguments":{"json":"{}"},"__proto__":{"polluted":true}}}',
    '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"audit_json","arguments":{"json":"{}","constructor":{"polluted":true}}}}',
    JSON.stringify({ jsonrpc: '2.0', id: 9, method: 'ping' }),
  ].join('\n') + '\n';
  const run = await runServerInput(lines);
  assert.equal(run.code, 0);
  assert.equal(run.stderr, '');
  const responses = parseNdjson(run.stdout);
  assert.equal(responses.length, 3);
  assert.equal(responses[0].error.code, -32600);
  assert.match(responses[0].error.data.reason, /prototype pollution key/);
  assert.equal(responses[1].error.code, -32600);
  assert.match(responses[1].error.data.reason, /prototype pollution key/);
  assert.equal(responses[2].id, 9);
  assert.deepEqual({}.polluted, undefined);
});

test('unknown tool names and invalid tool arguments return clean JSON-RPC errors', async () => {
  const run = await runServerInput(ndjsonInput([
    initializeMessage(1),
    {
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: 'definitely_not_a_tool', arguments: {} },
    },
    {
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: { name: 'audit_path', arguments: { path: 42 } },
    },
  ]));
  assert.equal(run.code, 0);
  assert.equal(run.stderr, '');
  const responses = parseNdjson(run.stdout);
  assert.equal(responses[1].error.code, -32602);
  assert.equal(responses[1].error.data.unknownTool, true);
  assert.equal(responses[2].error.code, -32602);
  assert.match(responses[2].error.data.reason, /path must be a string/);
});

test('JSON-RPC batch arrays and wrong version members are invalid requests', async () => {
  const run = await runServerInput(`[]\n{"jsonrpc":"2.1","id":1,"method":"ping"}\n`);
  assert.equal(run.code, 0);
  const responses = parseNdjson(run.stdout);
  assert.equal(responses.length, 2);
  assert.equal(responses[0].error.code, -32600);
  assert.equal(responses[1].error.code, -32600);
});

test('an oversized newline-delimited frame is bounded, rejected and resynchronized', async () => {
  const oversized = '{' + 'x'.repeat(DEFAULT_MAX_MESSAGE_BYTES + 32);
  const validPing = JSON.stringify({ jsonrpc: '2.0', id: 10, method: 'ping' });
  const run = await runServerInput(`${oversized}\n${validPing}\n`, { timeoutMs: 15000 });
  assert.equal(run.code, 0);
  assert.equal(run.stderr, '');
  const responses = parseNdjson(run.stdout);
  assert.equal(responses.length, 2);
  assert.equal(responses[0].error.code, -32700);
  assert.match(responses[0].error.data.reason, /exceeded/);
  assert.equal(responses[1].id, 10);
});

test('framer rejects oversized Content-Length frames and discards exactly their bodies', () => {
  const messages = [];
  const errors = [];
  const framer = new HybridJsonRpcFramer({
    maxMessageBytes: 64,
    onMessage: (text, framing) => messages.push({ text, framing }),
    onFramingError: (reason, framing) => errors.push({ reason, framing }),
  });
  const body = 'x'.repeat(100);
  const valid = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' });
  framer.write(Buffer.from(`Content-Length: 100\r\n\r\n${body}${valid}\n`));
  assert.equal(errors.length, 1);
  assert.match(errors[0].reason, /exceeded 64 bytes/);
  assert.equal(messages.length, 1);
  assert.equal(messages[0].text, valid);
  assert.equal(messages[0].framing, 'ndjson');
});

test('framer rejects LF-only Content-Length headers as malformed strict framing', () => {
  const messages = [];
  const errors = [];
  const framer = new HybridJsonRpcFramer({
    maxMessageBytes: 1024,
    onMessage: (text) => messages.push(text),
    onFramingError: (reason) => errors.push(reason),
  });
  framer.write(Buffer.from('Content-Length: 2\n\n{}\n'));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /CRLF CRLF/);
  assert.equal(messages.length, 0);
});

test('framer bounds malformed newline input that never terminates', () => {
  const errors = [];
  const framer = new HybridJsonRpcFramer({
    maxMessageBytes: 32,
    onMessage: () => {},
    onFramingError: (reason) => errors.push(reason),
  });
  framer.write(Buffer.from('x'.repeat(100)));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /exceeded 32 bytes/);
});
