import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const registryName = 'io.github.draarivpatel-ui/cage-mcp-server';
const repositoryUrl = 'https://github.com/draarivpatel-ui/cage-mcp-server';
const schemaUrl = 'https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json';

async function readJson(file) {
  return JSON.parse(await fs.readFile(path.join(root, file), 'utf8'));
}

test('server.json satisfies the current official MCP Registry npm contract', async () => {
  const server = await readJson('server.json');
  const pkg = await readJson('package.json');

  assert.deepEqual(Object.keys(server).sort(), [
    '$schema',
    'description',
    'name',
    'packages',
    'repository',
    'title',
    'version',
    'websiteUrl',
  ]);
  assert.equal(server.$schema, schemaUrl);
  assert.equal(server.name, registryName);
  assert.match(server.name, /^[a-zA-Z0-9.-]+\/[a-zA-Z0-9._-]+$/);
  assert.equal(server.name.split('/').length, 2);
  assert.equal(server.title, 'Cage Security');
  assert.equal(server.description, 'Offline AppSec firewall MCP server with deterministic security audit tools');
  assert.ok(server.description.length <= 100);
  assert.equal(server.version, pkg.version);
  assert.match(server.version, /^\d+\.\d+\.\d+$/);
  assert.equal(server.websiteUrl, repositoryUrl);
  assert.deepEqual(server.repository, {
    url: repositoryUrl,
    source: 'github',
    id: '1474695651',
  });

  assert.equal(Array.isArray(server.packages), true);
  assert.equal(server.packages.length, 1);
  assert.deepEqual(Object.keys(server.packages[0]).sort(), [
    'identifier',
    'registryBaseUrl',
    'registryType',
    'transport',
    'version',
  ]);
  assert.equal(server.packages[0].registryType, 'npm');
  assert.equal(server.packages[0].registryBaseUrl, 'https://registry.npmjs.org');
  assert.equal(server.packages[0].identifier, pkg.name);
  assert.equal(server.packages[0].version, server.version);
  assert.deepEqual(server.packages[0].transport, { type: 'stdio' });
});

test('glama.json declares the exact GitHub maintainer contract', async () => {
  const glama = await readJson('glama.json');
  assert.deepEqual(glama, {
    $schema: 'https://glama.ai/mcp/schemas/server.json',
    maintainers: ['draarivpatel-ui'],
  });
});

test('package.json metadata proves npm ownership and stays publish clean', async () => {
  const pkg = await readJson('package.json');
  assert.equal(pkg.mcpName, registryName);
  assert.equal(pkg.version, '1.0.0');
  assert.deepEqual(pkg.bin, { 'cage-mcp-server': 'bin/cage-mcp-server.mjs' });
  assert.deepEqual(pkg.files, [
    'bin/',
    'src/',
    'server.json',
    'glama.json',
    'README.md',
    'LICENSE',
    'SECURITY.md',
    'CHANGELOG.md',
  ]);
  assert.deepEqual(pkg.repository, {
    type: 'git',
    url: 'git+https://github.com/draarivpatel-ui/cage-mcp-server.git',
  });
  assert.equal(pkg.homepage, `${repositoryUrl}#readme`);
  assert.deepEqual(pkg.bugs, { url: `${repositoryUrl}/issues` });
  assert.equal(pkg.engines.node, '>=18');
  assert.equal(Array.isArray(pkg.keywords), true);
  assert.equal(new Set(pkg.keywords).size, pkg.keywords.length);
  for (const keyword of ['mcp', 'mcp-server', 'security', 'appsec']) {
    assert.equal(pkg.keywords.includes(keyword), true, `missing keyword ${keyword}`);
  }
});

test('npm pack dry run is clean, minimal and free of secret file shapes', async () => {
  const env = { ...process.env };
  delete env.npm_config_store_dir;
  delete env['npm_config_store-dir'];

  const npmExecPath = process.env.npm_execpath;
  const command = npmExecPath ? process.execPath : (process.platform === 'win32' ? 'npm.cmd' : 'npm');
  const args = npmExecPath
    ? [npmExecPath, 'pack', '--dry-run', '--json']
    : ['pack', '--dry-run', '--json'];
  const result = spawnSync(command, args, {
    cwd: root,
    env,
    encoding: 'utf8',
    timeout: 30000,
  });

  assert.equal(result.error, undefined);
  assert.equal(result.signal, null);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr.trim(), '', 'npm pack emitted warnings or diagnostics');

  const reports = JSON.parse(result.stdout);
  assert.equal(reports.length, 1);
  const report = reports[0];
  assert.equal(report.name, 'cage-mcp-server');
  assert.equal(report.version, '1.0.0');

  const expectedFiles = [
    'CHANGELOG.md',
    'LICENSE',
    'README.md',
    'SECURITY.md',
    'bin/cage-mcp-server.mjs',
    'glama.json',
    'package.json',
    'server.json',
    'src/server.mjs',
    'src/tools.mjs',
    'src/validation.mjs',
  ];
  const actualFiles = report.files.map((file) => file.path).sort();
  assert.deepEqual(actualFiles, expectedFiles.sort());
  assert.equal(report.entryCount, expectedFiles.length);
  assert.equal((report.bundled ?? []).length, 0);

  const secretFileShape = /(^|\/)(\.env(?:\..+)?|\.npmrc|id_rsa|id_dsa|id_ed25519|[^/]+\.pem|[^/]+\.key|[^/]+\.p12|[^/]+\.pfx)$/i;
  for (const file of report.files) {
    assert.equal(secretFileShape.test(file.path), false, `${file.path} looks like a secret file`);
  }
});
