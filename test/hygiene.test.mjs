import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));

async function walk(directory) {
  const output = [];
  const entries = await fs.readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name === '.git' || entry.name === 'node_modules') continue;
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      output.push(...await walk(absolute));
    } else if (entry.isFile()) {
      output.push(absolute);
    }
  }
  return output;
}

test('package dependencies are exactly the ten pinned live security packages', async () => {
  const pkg = JSON.parse(await fs.readFile(path.join(root, 'package.json'), 'utf8'));
  assert.deepEqual(Object.keys(pkg.dependencies).sort(), [
    'cookiecage',
    'corscage',
    'envcage',
    'headersafe',
    'jsoncage',
    'logcage',
    'pathcage',
    'redirectcage',
    'sentinel-lint',
    'zipcage',
  ]);
  for (const [name, version] of Object.entries(pkg.dependencies)) {
    assert.match(version, /^\d+\.\d+\.\d+$/, `${name} is not exactly pinned`);
  }
  assert.equal(Object.hasOwn(pkg.dependencies, 'fast-check'), false);
  assert.equal(Object.hasOwn(pkg.devDependencies, 'fast-check'), true);
  const fastCheckSpec = pkg.devDependencies['fast-check'];
  assert.match(
    fastCheckSpec,
    /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/,
    'fast-check must use an exact version, not a range',
  );
  const lock = JSON.parse(await fs.readFile(path.join(root, 'package-lock.json'), 'utf8'));
  assert.equal(lock.packages[''].devDependencies['fast-check'], fastCheckSpec);
  assert.equal(lock.packages['node_modules/fast-check'].version, fastCheckSpec);
  assert.equal(lock.packages['node_modules/fast-check'].dev, true);
  assert.equal(pkg.type, 'module');
  assert.equal(pkg.bin['cage-mcp-server'], 'bin/cage-mcp-server.mjs');
  assert.equal(pkg.engines.node, '>=18');
});

test('required public repository files are present and bin is executable', async () => {
  for (const file of [
    'README.md',
    'LICENSE',
    'SECURITY.md',
    'CONTRIBUTING.md',
    'CHANGELOG.md',
    '.gitignore',
    '.github/workflows/ci.yml',
    'src/server.mjs',
    'src/tools.mjs',
    'bin/cage-mcp-server.mjs',
    'package-lock.json',
  ]) {
    await fs.access(path.join(root, file));
  }
  const bin = await fs.readFile(path.join(root, 'bin/cage-mcp-server.mjs'), 'utf8');
  assert.match(bin, /^#!\/usr\/bin\/env node/);
  if (process.platform !== 'win32') {
    const mode = (await fs.stat(path.join(root, 'bin/cage-mcp-server.mjs'))).mode;
    assert.notEqual(mode & 0o111, 0);
  }
});

test('server version and package version stay synchronized', async () => {
  const pkg = JSON.parse(await fs.readFile(path.join(root, 'package.json'), 'utf8'));
  const server = await fs.readFile(path.join(root, 'src/server.mjs'), 'utf8');
  const match = /SERVER_VERSION = '([^']+)'/.exec(server);
  assert.equal(match?.[1], pkg.version);
});

test('repository text has no private paths, mailbox fragments, coauthor trailers or Unicode dash punctuation', async () => {
  const files = await walk(root);
  const forbidden = [
    { label: 'em dash', value: '\u2014' },
    { label: 'en dash', value: '\u2013' },
    { label: 'local user path', value: '/' + 'Users' + '/' },
    { label: 'personal mailbox', value: 'someone' + '@gmail' },
    { label: 'personal mailbox', value: 'handle-redacted286' + '@gmail' },
    { label: 'street fragment', value: '5019' + ' Exampleton' },
    { label: 'coauthor trailer', value: 'Co-Authored' + '-By:' },
  ];
  for (const file of files) {
    const stat = await fs.stat(file);
    if (stat.size > 3 * 1024 * 1024) continue;
    const text = await fs.readFile(file, 'utf8');
    for (const item of forbidden) {
      assert.equal(
        text.includes(item.value),
        false,
        `${path.relative(root, file)} contains ${item.label}`,
      );
    }
  }
});

test('workflow matrix is exactly Ubuntu and Windows across Node 18, 20, 22 and 24', async () => {
  const workflow = await fs.readFile(path.join(root, '.github/workflows/ci.yml'), 'utf8');
  assert.match(workflow, /os: \[ubuntu-latest, windows-latest\]/);
  assert.match(workflow, /node: \[18, 20, 22, 24\]/);
  assert.match(workflow, /npm ci/);
  assert.match(workflow, /npm test/);
  assert.match(workflow, /npm run smoke/);
});
