import assert from 'node:assert/strict';

import {
  contentLengthInput,
  initializeMessage,
  parseContentLengthFrames,
  runServerInput,
} from '../testkit/stdio.mjs';

const messages = [
  initializeMessage(1),
  { jsonrpc: '2.0', method: 'notifications/initialized' },
  { jsonrpc: '2.0', id: 2, method: 'tools/list' },
  {
    jsonrpc: '2.0',
    id: 3,
    method: 'tools/call',
    params: {
      name: 'audit_json',
      arguments: { json: '{"safe":true}' },
    },
  },
];

const run = await runServerInput(contentLengthInput(messages));
assert.equal(run.code, 0, run.stderr);
assert.equal(run.stderr, '');
const responses = parseContentLengthFrames(run.stdoutBuffer);
assert.equal(responses.length, 3);
assert.equal(responses[0].result.protocolVersion, '2025-11-25');
assert.equal(responses[1].result.tools.length, 10);
assert.equal(responses[2].result.structuredContent.ok, true);
console.log('smoke-mcp: initialize, tools/list and audit_json passed over stdio Content-Length framing');
