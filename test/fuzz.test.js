import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';

import { HybridJsonRpcFramer } from '../src/server.mjs';
import { ToolInputError, assertNoDangerousKeys } from '../src/validation.mjs';

const messageIds = fc.array(fc.integer({ min: 1, max: 1000000 }), { minLength: 1, maxLength: 8 });
const chunkSizes = fc.array(fc.integer({ min: 1, max: 23 }), { minLength: 1, maxLength: 32 });

function writeInChunks(framer, payload, sizes) {
  let offset = 0;
  for (const size of sizes) {
    if (offset >= payload.length) break;
    const end = Math.min(payload.length, offset + size);
    framer.write(payload.subarray(offset, end));
    offset = end;
  }
  if (offset < payload.length) framer.write(payload.subarray(offset));
}

function pingMessages(ids) {
  return ids.map((id) => JSON.stringify({ jsonrpc: '2.0', id, method: 'ping' }));
}

test('newline-delimited framing reassembles messages across arbitrary chunks', () => {
  fc.assert(
    fc.property(messageIds, chunkSizes, (ids, sizes) => {
      const expected = pingMessages(ids);
      const payload = Buffer.from(`${expected.join('\n')}\n`);
      const received = [];
      const errors = [];
      const framer = new HybridJsonRpcFramer({
        maxMessageBytes: 4096,
        onMessage: (text, framing) => received.push({ text, framing }),
        onFramingError: (reason) => errors.push(reason),
      });

      writeInChunks(framer, payload, sizes);
      assert.deepEqual(received, expected.map((text) => ({ text, framing: 'ndjson' })));
      assert.deepEqual(errors, []);
    }),
    { numRuns: 100 },
  );
});

test('Content-Length framing reassembles messages across arbitrary chunks', () => {
  fc.assert(
    fc.property(messageIds, chunkSizes, (ids, sizes) => {
      const expected = pingMessages(ids);
      const payload = Buffer.from(expected.map((text) => `Content-Length: ${Buffer.byteLength(text)}\r\n\r\n${text}`).join(''));
      const received = [];
      const errors = [];
      const framer = new HybridJsonRpcFramer({
        maxMessageBytes: 4096,
        onMessage: (text, framing) => received.push({ text, framing }),
        onFramingError: (reason) => errors.push(reason),
      });

      writeInChunks(framer, payload, sizes);
      assert.deepEqual(received, expected.map((text) => ({ text, framing: 'content-length' })));
      assert.deepEqual(errors, []);
    }),
    { numRuns: 100 },
  );
});

test('prototype-pollution keys are rejected at generated nesting positions', () => {
  fc.assert(
    fc.property(
      fc.constantFrom('__proto__', 'constructor', 'prototype'),
      fc.array(fc.boolean(), { minLength: 0, maxLength: 6 }),
      (key, wrappers) => {
        let current = { [key]: true };
        for (const useArray of wrappers) {
          current = useArray ? [current] : { nested: current };
        }
        const input = JSON.parse(JSON.stringify(current));
        assert.throws(
          () => assertNoDangerousKeys(input),
          (error) => error instanceof ToolInputError,
        );
      },
    ),
    { numRuns: 100 },
  );
});
