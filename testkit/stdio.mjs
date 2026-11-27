import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const repoRoot = fileURLToPath(new URL('../', import.meta.url));
export const serverBin = fileURLToPath(new URL('../bin/cage-mcp-server.mjs', import.meta.url));

export function ndjsonInput(messages) {
  return messages.map((message) => JSON.stringify(message)).join('\n') + '\n';
}

export function contentLengthInput(messages) {
  let output = '';
  for (const message of messages) {
    const body = JSON.stringify(message);
    output += `Content-Length: ${Buffer.byteLength(body, 'utf8')}\r\n\r\n${body}`;
  }
  return output;
}

export function parseNdjson(stdout) {
  return stdout.split('\n').filter((line) => line.trim() !== '').map((line) => JSON.parse(line));
}

export function parseContentLengthFrames(stdoutBuffer) {
  const frames = [];
  let offset = 0;
  while (offset < stdoutBuffer.length) {
    const headerEnd = stdoutBuffer.indexOf('\r\n\r\n', offset);
    if (headerEnd === -1) throw new Error('missing frame header terminator');
    const header = stdoutBuffer.subarray(offset, headerEnd).toString('latin1');
    const match = /^Content-Length: (\d+)$/i.exec(header);
    if (match === null) throw new Error(`missing Content-Length in ${header}`);
    const length = Number(match[1]);
    const start = headerEnd + 4;
    const end = start + length;
    if (end > stdoutBuffer.length) throw new Error('truncated frame body');
    frames.push(JSON.parse(stdoutBuffer.subarray(start, end).toString('utf8')));
    offset = end;
  }
  return frames;
}

export async function runServerInput(input, { timeoutMs = 10000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [serverBin], {
      cwd: repoRoot,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const stdoutChunks = [];
    const stderrChunks = [];
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill();
      reject(new Error('server subprocess timed out'));
    }, timeoutMs);

    child.stdout.on('data', (chunk) => stdoutChunks.push(chunk));
    child.stderr.on('data', (chunk) => stderrChunks.push(chunk));
    child.on('error', (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    });
    child.on('close', (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        code,
        signal,
        stdoutBuffer: Buffer.concat(stdoutChunks),
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        stderr: Buffer.concat(stderrChunks).toString('utf8'),
      });
    });

    child.stdin.write(input);
    child.stdin.end();
  });
}

export function initializeMessage(id = 1) {
  return {
    jsonrpc: '2.0',
    id,
    method: 'initialize',
    params: {
      protocolVersion: '2025-11-25',
      capabilities: {},
      clientInfo: { name: 'cage-test-client', version: '0.0.0' },
    },
  };
}
