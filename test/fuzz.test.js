import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';

import { HybridJsonRpcFramer } from '../src/server.mjs';
import { ToolInputError, assertNoDangerousKeys } from '../src/validation.mjs';

const DEFAULT_FUZZ_SEED = 20261127;

function fuzzSeed() {
  const raw = process.env.FUZZ_SEED;
  if (raw === undefined) return DEFAULT_FUZZ_SEED;
  if (!/^-?\d+$/.test(raw)) throw new Error('FUZZ_SEED must be an integer');
  const seed = Number(raw);
  if (!Number.isSafeInteger(seed)) throw new Error('FUZZ_SEED must be a safe integer');
  return seed;
}

const multibyteUnit = fc.constantFrom(
  String.fromCodePoint(0x00e9),
  String.fromCodePoint(0x4e2d),
  String.fromCodePoint(0x6587),
  String.fromCodePoint(0x1f600),
  String.fromCodePoint(0x1f680),
);
const multibyteText = fc.array(multibyteUnit, { minLength: 1, maxLength: 10 }).map((parts) => parts.join(''));
const messageCases = fc.array(
  fc.tuple(fc.integer({ min: 1, max: 1000000 }), multibyteText),
  { minLength: 1, maxLength: 8 },
);
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

function pingMessages(cases) {
  return cases.map(([id, echo]) => JSON.stringify({
    jsonrpc: '2.0',
    id,
    method: 'ping',
    params: { echo },
  }));
}

function contentLengthFrame(text) {
  return `Content-Length: ${Buffer.byteLength(text, 'utf8')}\r\n\r\n${text}`;
}

function assertMultibyteFrames(texts) {
  for (const text of texts) {
    assert.ok(Buffer.byteLength(text, 'utf8') > text.length, 'generated frame must require byte counting');
  }
}

function makeFramer(maxMessageBytes, received, errors) {
  return new HybridJsonRpcFramer({
    maxMessageBytes,
    onMessage: (text, framing) => received.push({ text, framing }),
    onFramingError: (reason, framing) => errors.push({ reason, framing }),
  });
}

test('newline-delimited framing reassembles multibyte messages across arbitrary chunks', () => {
  fc.assert(
    fc.property(messageCases, chunkSizes, (cases, sizes) => {
      const expected = pingMessages(cases);
      assertMultibyteFrames(expected);
      const payload = Buffer.from(`${expected.join('\n')}\n`, 'utf8');
      const received = [];
      const errors = [];
      const framer = makeFramer(4096, received, errors);

      writeInChunks(framer, payload, sizes);
      assert.deepEqual(received, expected.map((text) => ({ text, framing: 'ndjson' })));
      assert.deepEqual(errors, []);
    }),
    { numRuns: 100, seed: fuzzSeed() },
  );
});

test('Content-Length framing reassembles multibyte messages across arbitrary chunks', () => {
  fc.assert(
    fc.property(messageCases, chunkSizes, (cases, sizes) => {
      const expected = pingMessages(cases);
      assertMultibyteFrames(expected);
      const payload = Buffer.from(expected.map((text) => contentLengthFrame(text)).join(''), 'utf8');
      const received = [];
      const errors = [];
      const framer = makeFramer(4096, received, errors);

      writeInChunks(framer, payload, sizes);
      assert.deepEqual(received, expected.map((text) => ({ text, framing: 'content-length' })));
      assert.deepEqual(errors, []);
    }),
    { numRuns: 100, seed: fuzzSeed() },
  );
});

const malformedHeaderCases = fc.constantFrom(
  {
    header: 'Content-Length: 5\r\nX-Test: yes',
    reason: 'unsupported header X-Test',
  },
  {
    header: 'Content-Length: 5\r\nContent-Length: 5',
    reason: 'duplicate Content-Length header',
  },
  {
    header: 'Content-Length: 5\r\nContent-Type: text/plain',
    reason: 'Content-Type must be application/json',
  },
  {
    header: 'Content-Length: 5\r\nbroken',
    reason: 'malformed header line',
  },
);

test('Content-Length framing rejects malformed headers, discards bodies and recovers', () => {
  fc.assert(
    fc.property(malformedHeaderCases, chunkSizes, (malformed, sizes) => {
      const validText = JSON.stringify({ jsonrpc: '2.0', id: 99, method: 'ping' });
      const payload = Buffer.from(`${malformed.header}\r\n\r\nabcde${contentLengthFrame(validText)}`, 'utf8');
      const received = [];
      const errors = [];
      const framer = makeFramer(4096, received, errors);

      writeInChunks(framer, payload, sizes);
      assert.deepEqual(errors, [{ reason: malformed.reason, framing: 'content-length' }]);
      assert.deepEqual(received, [{ text: validText, framing: 'content-length' }]);
    }),
    { numRuns: 100, seed: fuzzSeed() },
  );
});

test('Content-Length framing rejects oversized frames, discards bodies and recovers', () => {
  fc.assert(
    fc.property(fc.integer({ min: 65, max: 160 }), chunkSizes, (oversizedLength, sizes) => {
      const validText = JSON.stringify({ jsonrpc: '2.0', id: 100, method: 'ping' });
      assert.ok(Buffer.byteLength(validText, 'utf8') <= 64);
      const body = 'x'.repeat(oversizedLength);
      const payload = Buffer.from(
        `Content-Length: ${oversizedLength}\r\n\r\n${body}${contentLengthFrame(validText)}`,
        'utf8',
      );
      const received = [];
      const errors = [];
      const framer = makeFramer(64, received, errors);

      writeInChunks(framer, payload, sizes);
      assert.deepEqual(errors, [{ reason: 'Content-Length frame exceeded 64 bytes', framing: 'content-length' }]);
      assert.deepEqual(received, [{ text: validText, framing: 'content-length' }]);
    }),
    { numRuns: 100, seed: fuzzSeed() },
  );
});

test('newline-delimited framing rejects oversized lines, discards them and recovers', () => {
  fc.assert(
    fc.property(fc.integer({ min: 65, max: 160 }), chunkSizes, (oversizedLength, sizes) => {
      const validText = JSON.stringify({ jsonrpc: '2.0', id: 101, method: 'ping' });
      assert.ok(Buffer.byteLength(validText, 'utf8') <= 64);
      const payload = Buffer.from(`${'x'.repeat(oversizedLength)}\n${validText}\n`, 'utf8');
      const received = [];
      const errors = [];
      const framer = makeFramer(64, received, errors);

      writeInChunks(framer, payload, sizes);
      assert.deepEqual(errors, [{ reason: 'newline-delimited message exceeded 64 bytes', framing: 'ndjson' }]);
      assert.deepEqual(received, [{ text: validText, framing: 'ndjson' }]);
    }),
    { numRuns: 100, seed: fuzzSeed() },
  );
});

const invalidUtf8Bodies = [
  Buffer.from([0xff]),
  Buffer.from([0xc3]),
  Buffer.from([0xe2, 0x82]),
  Buffer.from([0xf0, 0x9f]),
  Buffer.from([0x80]),
];
const invalidUtf8Body = fc.integer({ min: 0, max: invalidUtf8Bodies.length - 1 }).map((index) => invalidUtf8Bodies[index]);

test('Content-Length framing rejects invalid UTF-8 bodies and recovers', () => {
  fc.assert(
    fc.property(invalidUtf8Body, chunkSizes, (invalidBody, sizes) => {
      const validText = JSON.stringify({ jsonrpc: '2.0', id: 102, method: 'ping' });
      const payload = Buffer.concat([
        Buffer.from(`Content-Length: ${invalidBody.length}\r\n\r\n`, 'utf8'),
        invalidBody,
        Buffer.from(contentLengthFrame(validText), 'utf8'),
      ]);
      const received = [];
      const errors = [];
      const framer = makeFramer(4096, received, errors);

      writeInChunks(framer, payload, sizes);
      assert.deepEqual(errors, [{ reason: 'frame body is not valid UTF-8', framing: 'content-length' }]);
      assert.deepEqual(received, [{ text: validText, framing: 'content-length' }]);
    }),
    { numRuns: 100, seed: fuzzSeed() },
  );
});

test('prototype-pollution keys are rejected while safe objects of the same shape pass', () => {
  fc.assert(
    fc.property(
      fc.constantFrom('__proto__', 'constructor', 'prototype'),
      fc.array(fc.boolean(), { minLength: 0, maxLength: 6 }),
      (key, wrappers) => {
        let rejected = { [key]: true };
        let accepted = { safe: true };
        for (const useArray of wrappers) {
          rejected = useArray ? [rejected] : { nested: rejected };
          accepted = useArray ? [accepted] : { nested: accepted };
        }
        const input = JSON.parse(JSON.stringify(rejected));
        const safeInput = JSON.parse(JSON.stringify(accepted));
        assert.throws(
          () => assertNoDangerousKeys(input),
          (error) => error instanceof ToolInputError,
        );
        assert.equal(assertNoDangerousKeys(safeInput), undefined);
      },
    ),
    { numRuns: 100, seed: fuzzSeed() },
  );
});
