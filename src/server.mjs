import { TextDecoder } from 'node:util';

import { callTool, TOOL_DEFINITIONS } from './tools.mjs';
import {
  ToolInputError,
  assertNoDangerousKeys,
  isPlainObject,
} from './validation.mjs';

export const SERVER_NAME = 'cage-mcp-server';
export const SERVER_VERSION = '1.0.0';
export const LATEST_PROTOCOL_VERSION = '2025-11-25';
export const SUPPORTED_PROTOCOL_VERSIONS = Object.freeze([
  '2024-11-05',
  '2025-03-26',
  '2025-06-18',
  '2025-11-25',
]);
export const DEFAULT_MAX_MESSAGE_BYTES = 2 * 1024 * 1024;
export const DEFAULT_MAX_HEADER_BYTES = 8192;

const JSON_RPC_PARSE_ERROR = -32700;
const JSON_RPC_INVALID_REQUEST = -32600;
const JSON_RPC_METHOD_NOT_FOUND = -32601;
const JSON_RPC_INVALID_PARAMS = -32602;
const JSON_RPC_INTERNAL_ERROR = -32603;

function jsonRpcError(id, code, message, data) {
  const error = { code, message };
  if (data !== undefined) error.data = data;
  return { jsonrpc: '2.0', id: id ?? null, error };
}

function jsonRpcResult(id, result) {
  return { jsonrpc: '2.0', id, result };
}

function decodeUtf8(buffer) {
  return new TextDecoder('utf-8', { fatal: true }).decode(buffer);
}

function laxContentLength(rawHeader) {
  for (const line of rawHeader.split('\n')) {
    const separator = line.indexOf(':');
    if (separator <= 0) continue;
    if (line.slice(0, separator).trim().toLowerCase() !== 'content-length') continue;
    const value = line.slice(separator + 1).trim();
    if (!/^\d{1,15}$/.test(value)) return null;
    const length = Number(value);
    return Number.isSafeInteger(length) && length > 0 ? length : null;
  }
  return null;
}

export class HybridJsonRpcFramer {
  constructor({
    onMessage,
    onFramingError,
    maxMessageBytes = DEFAULT_MAX_MESSAGE_BYTES,
    maxHeaderBytes = DEFAULT_MAX_HEADER_BYTES,
  }) {
    if (typeof onMessage !== 'function') throw new TypeError('onMessage callback is required');
    if (typeof onFramingError !== 'function') throw new TypeError('onFramingError callback is required');
    this.onMessage = onMessage;
    this.onFramingError = onFramingError;
    this.maxMessageBytes = maxMessageBytes;
    this.maxHeaderBytes = maxHeaderBytes;
    this.buffer = Buffer.alloc(0);
    this.state = 'scan';
    this.contentLength = 0;
    this.discardBytes = 0;
  }

  write(chunk) {
    if (!Buffer.isBuffer(chunk)) chunk = Buffer.from(chunk);
    this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
    this.process();
  }

  end() {
    if (this.buffer.length > 0 || this.state === 'body' || this.state === 'header') {
      this.onFramingError('stream ended in the middle of a frame', this.state === 'scan' ? 'ndjson' : this.state);
      this.buffer = Buffer.alloc(0);
      this.state = 'scan';
    }
  }

  consume(count) {
    this.buffer = this.buffer.subarray(count);
  }

  process() {
    for (;;) {
      if (this.state === 'scan') {
        if (!this.scanBoundary()) return;
        continue;
      }
      if (this.state === 'header') {
        if (!this.readHeader()) return;
        continue;
      }
      if (this.state === 'body') {
        if (!this.readBody()) return;
        continue;
      }
      if (this.state === 'ndjson') {
        if (!this.readNdjsonLine()) return;
        continue;
      }
      if (this.state === 'discard-line') {
        if (!this.discardLine()) return;
        continue;
      }
      if (this.state === 'discard-bytes') {
        if (!this.discardBodyBytes()) return;
        continue;
      }
      throw new Error(`unknown framer state ${this.state}`);
    }
  }

  scanBoundary() {
    if (this.buffer.length === 0) return false;

    if (this.buffer[0] === 0x0a) {
      this.consume(1);
      return true;
    }
    if (this.buffer[0] === 0x0d) {
      if (this.buffer.length === 1) return false;
      if (this.buffer[1] === 0x0a) {
        this.consume(2);
        return true;
      }
    }

    const prefix = 'content-length:';
    const compareLength = Math.min(this.buffer.length, prefix.length);
    const actual = this.buffer.subarray(0, compareLength).toString('latin1').toLowerCase();
    const expected = prefix.slice(0, compareLength);
    if (actual === expected) {
      if (this.buffer.length < prefix.length) return false;
      this.state = 'header';
      return true;
    }

    this.state = 'ndjson';
    return true;
  }

  readHeader() {
    const end = this.buffer.indexOf('\r\n\r\n');
    if (end === -1) {
      const laxEnd = this.buffer.indexOf('\n\n');
      if (laxEnd !== -1) {
        const laxHeader = this.buffer.subarray(0, laxEnd).toString('latin1');
        this.consume(laxEnd + 2);
        const length = laxContentLength(laxHeader);
        this.state = length === null ? 'scan' : 'discard-bytes';
        this.discardBytes = length ?? 0;
        this.onFramingError('Content-Length headers must terminate with CRLF CRLF', 'content-length');
        return true;
      }
      if (this.buffer.length > this.maxHeaderBytes) {
        this.buffer = Buffer.alloc(0);
        this.state = 'discard-line';
        this.onFramingError('Content-Length header block exceeded the bounded size', 'content-length');
        return true;
      }
      return false;
    }

    const rawHeader = this.buffer.subarray(0, end).toString('latin1');
    this.consume(end + 4);
    const parsed = this.parseHeaderBlock(rawHeader);
    if (!parsed.ok) {
      this.state = parsed.length !== null && parsed.length > 0 ? 'discard-bytes' : 'scan';
      this.discardBytes = parsed.length ?? 0;
      this.onFramingError(parsed.reason, 'content-length');
      return true;
    }

    if (parsed.length > this.maxMessageBytes) {
      this.state = 'discard-bytes';
      this.discardBytes = parsed.length;
      this.onFramingError(`Content-Length frame exceeded ${this.maxMessageBytes} bytes`, 'content-length');
      return true;
    }

    this.contentLength = parsed.length;
    this.state = 'body';
    return true;
  }

  parseHeaderBlock(rawHeader) {
    const lines = rawHeader.split('\r\n');
    let length = null;
    let contentTypeSeen = false;

    for (const line of lines) {
      const separator = line.indexOf(':');
      if (separator <= 0) return { ok: false, reason: 'malformed header line', length };
      const name = line.slice(0, separator);
      const value = line.slice(separator + 1);
      if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(name)) {
        return { ok: false, reason: 'malformed header name', length };
      }
      if (!/^[ \t].*[^ \t]$|^[ \t][^ \t]$/.test(value) && value.trim() !== value) {
        return { ok: false, reason: 'malformed header whitespace', length };
      }
      const normalizedName = name.toLowerCase();
      const normalizedValue = value.trim();
      if (normalizedName === 'content-length') {
        if (length !== null) return { ok: false, reason: 'duplicate Content-Length header', length };
        if (!/^\d{1,15}$/.test(normalizedValue)) {
          return { ok: false, reason: 'Content-Length must be decimal digits', length };
        }
        length = Number(normalizedValue);
        if (!Number.isSafeInteger(length) || length <= 0) {
          return { ok: false, reason: 'Content-Length must be a positive safe integer', length: null };
        }
      } else if (normalizedName === 'content-type') {
        if (contentTypeSeen) return { ok: false, reason: 'duplicate Content-Type header', length };
        contentTypeSeen = true;
        if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(normalizedValue)) {
          return { ok: false, reason: 'Content-Type must be application/json', length };
        }
      } else {
        return { ok: false, reason: `unsupported header ${name}`, length };
      }
    }

    if (length === null) return { ok: false, reason: 'missing Content-Length header', length };
    return { ok: true, length };
  }

  readBody() {
    if (this.buffer.length < this.contentLength) return false;
    const body = this.buffer.subarray(0, this.contentLength);
    this.consume(this.contentLength);
    this.contentLength = 0;
    this.state = 'scan';
    try {
      this.onMessage(decodeUtf8(body), 'content-length');
    } catch {
      this.onFramingError('frame body is not valid UTF-8', 'content-length');
    }
    return true;
  }

  readNdjsonLine() {
    const newline = this.buffer.indexOf(0x0a);
    if (newline === -1) {
      if (this.buffer.length > this.maxMessageBytes) {
        this.buffer = Buffer.alloc(0);
        this.state = 'discard-line';
        this.onFramingError(`newline-delimited message exceeded ${this.maxMessageBytes} bytes`, 'ndjson');
        return true;
      }
      return false;
    }

    const line = this.buffer.subarray(0, newline);
    this.consume(newline + 1);
    this.state = 'scan';

    if (line.length > this.maxMessageBytes) {
      this.onFramingError(`newline-delimited message exceeded ${this.maxMessageBytes} bytes`, 'ndjson');
      return true;
    }

    const withoutCarriageReturn = line.length > 0 && line[line.length - 1] === 0x0d
      ? line.subarray(0, line.length - 1)
      : line;
    if (withoutCarriageReturn.length === 0 || withoutCarriageReturn.every((byte) => byte === 0x20 || byte === 0x09)) {
      return true;
    }

    try {
      this.onMessage(decodeUtf8(withoutCarriageReturn), 'ndjson');
    } catch {
      this.onFramingError('newline-delimited message is not valid UTF-8', 'ndjson');
    }
    return true;
  }

  discardLine() {
    const newline = this.buffer.indexOf(0x0a);
    if (newline === -1) {
      this.buffer = Buffer.alloc(0);
      return false;
    }
    this.consume(newline + 1);
    this.state = 'scan';
    return true;
  }

  discardBodyBytes() {
    if (this.buffer.length === 0) return false;
    const count = Math.min(this.buffer.length, this.discardBytes);
    this.consume(count);
    this.discardBytes -= count;
    if (this.discardBytes > 0) return false;
    this.state = 'scan';
    return true;
  }
}

function validateRequestId(message) {
  if (!Object.hasOwn(message, 'id')) return { present: false, valid: true, id: null };
  const id = message.id;
  if (id === null) return { present: true, valid: true, id };
  if (typeof id === 'string' && id.length <= 256) return { present: true, valid: true, id };
  if (Number.isInteger(id) && Number.isSafeInteger(id)) return { present: true, valid: true, id };
  return { present: true, valid: false, id: null };
}

function invalidRequest(message, detail) {
  return jsonRpcError(null, JSON_RPC_INVALID_REQUEST, 'Invalid Request', { reason: detail ?? message });
}

function toolSuccess(payload) {
  const text = JSON.stringify(payload, null, 2);
  return {
    content: [{ type: 'text', text }],
    structuredContent: payload,
    isError: false,
  };
}

function toolExecutionFailure(error) {
  const payload = {
    ok: false,
    error: {
      code: typeof error?.code === 'string' ? error.code : 'CAGE_MCP_TOOL_ERROR',
      reason: typeof error?.message === 'string' ? error.message : String(error),
    },
  };
  return {
    content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }],
    structuredContent: payload,
    isError: true,
  };
}

function initializeResult(params) {
  if (!isPlainObject(params)) {
    throw new ToolInputError('initialize params must be an object', 'params');
  }
  if (typeof params.protocolVersion !== 'string' || params.protocolVersion.length > 64) {
    throw new ToolInputError('initialize params.protocolVersion must be a string', 'params.protocolVersion');
  }
  const protocolVersion = SUPPORTED_PROTOCOL_VERSIONS.includes(params.protocolVersion)
    ? params.protocolVersion
    : LATEST_PROTOCOL_VERSION;
  return {
    protocolVersion,
    capabilities: {
      tools: {
        listChanged: false,
      },
    },
    serverInfo: {
      name: SERVER_NAME,
      version: SERVER_VERSION,
    },
    instructions: 'Offline deterministic AppSec tools. Pass only bounded snippets, payloads and policy data; do not send secret values unless redaction or validation is the explicit task.',
  };
}

export async function handleJsonRpcMessage(message) {
  if (!isPlainObject(message)) return invalidRequest(null, 'message must be one JSON-RPC object');
  if (message.jsonrpc !== '2.0') return invalidRequest(null, 'jsonrpc must be exactly "2.0"');
  if (typeof message.method !== 'string' || message.method.length === 0 || message.method.length > 128) {
    return invalidRequest(null, 'method must be a non-empty bounded string');
  }

  const idState = validateRequestId(message);
  if (!idState.valid) return invalidRequest(null, 'id must be a string, safe integer or null');
  const isNotification = !idState.present;
  const id = idState.id;

  try {
    assertNoDangerousKeys(message);
  } catch (error) {
    return invalidRequest(null, error.message);
  }

  if (message.method.startsWith('notifications/')) {
    return null;
  }

  if (isNotification) {
    if (message.method === 'initialize') {
      return jsonRpcError(null, JSON_RPC_INVALID_REQUEST, 'Invalid Request', {
        reason: 'initialize must be a request with an id',
      });
    }
    return null;
  }

  if (message.method === 'initialize') {
    try {
      return jsonRpcResult(id, initializeResult(message.params));
    } catch (error) {
      return jsonRpcError(id, JSON_RPC_INVALID_PARAMS, 'Invalid params', { reason: error.message });
    }
  }

  if (message.method === 'ping') {
    return jsonRpcResult(id, {});
  }

  if (message.method === 'tools/list') {
    if (message.params !== undefined && !isPlainObject(message.params)) {
      return jsonRpcError(id, JSON_RPC_INVALID_PARAMS, 'Invalid params', { reason: 'tools/list params must be an object when present' });
    }
    return jsonRpcResult(id, { tools: TOOL_DEFINITIONS });
  }

  if (message.method === 'tools/call') {
    if (!isPlainObject(message.params)) {
      return jsonRpcError(id, JSON_RPC_INVALID_PARAMS, 'Invalid params', { reason: 'tools/call params must be an object' });
    }
    const allowed = new Set(['name', 'arguments', '_meta', 'task']);
    for (const key of Object.keys(message.params)) {
      if (!allowed.has(key)) {
        return jsonRpcError(id, JSON_RPC_INVALID_PARAMS, 'Invalid params', { reason: `unknown tools/call param "${key}"` });
      }
    }
    if (typeof message.params.name !== 'string' || message.params.name.length === 0 || message.params.name.length > 128) {
      return jsonRpcError(id, JSON_RPC_INVALID_PARAMS, 'Invalid params', { reason: 'tools/call params.name must be a bounded string' });
    }

    try {
      const payload = await callTool(message.params.name, message.params.arguments);
      return jsonRpcResult(id, toolSuccess(payload));
    } catch (error) {
      if (error instanceof ToolInputError) {
        return jsonRpcError(id, JSON_RPC_INVALID_PARAMS, 'Invalid params', {
          reason: error.message,
          field: error.field,
          unknownTool: error.unknownTool === true,
        });
      }
      return jsonRpcResult(id, toolExecutionFailure(error));
    }
  }

  return jsonRpcError(id, JSON_RPC_METHOD_NOT_FOUND, 'Method not found', { method: message.method });
}

export class CageMcpServer {
  constructor({
    input,
    output,
    maxMessageBytes = DEFAULT_MAX_MESSAGE_BYTES,
    maxHeaderBytes = DEFAULT_MAX_HEADER_BYTES,
  }) {
    this.input = input;
    this.output = output;
    this.outputBroken = false;
    this.outputDraining = false;
    this.inputEnded = false;
    this.pendingRpc = 0;
    if (output !== undefined && typeof output.on === 'function') {
      output.on('error', () => {
        this.outputBroken = true;
        if (input !== undefined && typeof input.destroy === 'function') input.destroy();
      });
      output.on('drain', () => {
        this.outputDraining = false;
        this.maybeResumeInput();
      });
    }
    this.queue = Promise.resolve();
    this.framer = new HybridJsonRpcFramer({
      maxMessageBytes,
      maxHeaderBytes,
      onMessage: (text, framing) => this.acceptFrame(text, framing),
      onFramingError: (reason, framing) => this.write(
        jsonRpcError(null, JSON_RPC_PARSE_ERROR, 'Parse error', { reason }),
        framing === 'content-length' ? 'content-length' : 'ndjson',
      ),
    });
  }

  start() {
    this.input.on('data', (chunk) => {
      this.pauseInput();
      this.framer.write(chunk);
      if (this.pendingRpc === 0) queueMicrotask(() => this.maybeResumeInput());
    });
    this.input.on('end', () => {
      this.inputEnded = true;
      this.framer.end();
    });
    this.input.on('error', () => {
      this.inputEnded = true;
    });
    return this;
  }

  pauseInput() {
    if (this.input !== undefined && typeof this.input.pause === 'function') this.input.pause();
  }

  maybeResumeInput() {
    if (this.inputEnded || this.outputDraining || this.pendingRpc > 0) return;
    if (this.input !== undefined && typeof this.input.resume === 'function') this.input.resume();
  }

  acceptFrame(text, framing) {
    let message;
    try {
      message = JSON.parse(text);
    } catch (error) {
      this.write(jsonRpcError(null, JSON_RPC_PARSE_ERROR, 'Parse error', {
        reason: error instanceof Error ? error.message : String(error),
      }), framing);
      return;
    }

    this.pendingRpc += 1;
    this.queue = this.queue.then(async () => {
      try {
        const response = await handleJsonRpcMessage(message);
        if (response !== null) this.write(response, framing);
      } catch (error) {
        this.write(jsonRpcError(null, JSON_RPC_INTERNAL_ERROR, 'Internal error', {
          reason: error instanceof Error ? error.message : String(error),
        }), framing);
      } finally {
        this.pendingRpc -= 1;
        this.maybeResumeInput();
      }
    });
  }

  write(message, framing) {
    if (this.outputBroken) return;
    const body = JSON.stringify(message);
    try {
      let acceptingWrites;
      if (framing === 'content-length') {
        acceptingWrites = this.output.write(`Content-Length: ${Buffer.byteLength(body, 'utf8')}\r\n\r\n${body}`);
      } else {
        acceptingWrites = this.output.write(`${body}\n`);
      }
      if (acceptingWrites === false) {
        this.outputDraining = true;
        this.pauseInput();
      }
    } catch {
      this.outputBroken = true;
    }
  }
}

export function createMcpServer(options = {}) {
  return new CageMcpServer(options);
}

export function runStdioServer(options = {}) {
  const server = new CageMcpServer({
    input: options.input ?? process.stdin,
    output: options.output ?? process.stdout,
    maxMessageBytes: options.maxMessageBytes,
    maxHeaderBytes: options.maxHeaderBytes,
  });
  return server.start();
}
