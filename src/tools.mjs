import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { scan } from 'sentinel-lint';
import { resolveSafePath } from 'pathcage';
import {
  assertSafeHeaderName,
  assertSafeHeaderValue,
  auditCsp,
  auditSetCookie,
  buildSecurityHeaders,
} from 'headersafe';
import { parseRedirectLocation } from 'redirectcage';
import { defineEnv, parseDotEnv, t } from 'envcage';
import { parseCookieHeader, serializeCookie } from 'cookiecage';
import { inspectZipBuffer } from 'zipcage';
import { redactSecrets, sanitizeLogLine, sanitizeLogRecord } from 'logcage';
import { createCorsPolicy, lintCorsPolicy } from 'corscage';
import { inspectJsonPayload } from 'jsoncage';

import {
  ToolInputError,
  assertArgumentsObject,
  assertNoDangerousKeys,
  assertOnlyKeys,
  enumValue,
  isPlainObject,
  optionalBoolean,
  optionalEnum,
  optionalInteger,
  optionalString,
  optionalStringArray,
  optionalStringOrArray,
  packageErrorPayload,
  requiredString,
  stringArray,
  stringValue,
} from './validation.mjs';

const MAX_SNIPPET_BYTES = 1024 * 1024;
const MAX_FINDINGS_RETURNED = 200;
const MAX_ZIP_ENTRIES_RETURNED = 100;
const MAX_BASE64_ARCHIVE_CHARS = 1024 * 1024;

function errorPayload(error) {
  return packageErrorPayload(error);
}

function auditFailure(error, extra = {}) {
  return {
    ok: false,
    error: errorPayload(error),
    ...extra,
  };
}

function requireOne(object, keys) {
  if (!keys.some((key) => object[key] !== undefined)) {
    throw new ToolInputError(`one of these properties is required: ${keys.join(', ')}`, keys[0]);
  }
}

function absoluteRoot(value) {
  if (!path.isAbsolute(value) && !/^[A-Za-z]:[\\/]/.test(value) && !value.startsWith('\\\\')) {
    throw new ToolInputError('root must be an absolute path so the audit never resolves against the server working directory', 'root');
  }
  return value;
}

function limitedFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  return {
    items: list.slice(0, MAX_FINDINGS_RETURNED),
    total: list.length,
    truncated: list.length > MAX_FINDINGS_RETURNED,
  };
}

function auditPath(rawArgs) {
  const args = assertArgumentsObject(rawArgs);
  assertOnlyKeys(args, ['path', 'root', 'decodeCheck', 'maxPathLength']);
  const input = requiredString(args, 'path', { maxLength: 4096 });
  const root = absoluteRoot(optionalString(args, 'root', { minLength: 1, maxLength: 4096 }) ?? '/sandbox');
  const options = {
    root,
    decodeCheck: optionalBoolean(args, 'decodeCheck') ?? false,
    maxPathLength: optionalInteger(args, 'maxPathLength', { min: 1, max: 8192 }) ?? 4096,
  };

  try {
    const resolved = resolveSafePath(input, options);
    return {
      ok: true,
      safe: true,
      root,
      resolvedPath: resolved,
      inputLength: input.length,
    };
  } catch (error) {
    return auditFailure(error, {
      safe: false,
      root,
      inputLength: input.length,
    });
  }
}

function headerRecordFromInput(value) {
  if (!isPlainObject(value)) {
    throw new ToolInputError('headers must be an object mapping header names to string values', 'headers');
  }
  const entries = Object.entries(value);
  if (entries.length > 100) {
    throw new ToolInputError('headers must contain at most 100 entries', 'headers');
  }
  const headers = new Map();
  const validationFindings = [];

  for (const [name, rawValue] of entries) {
    if (name.length > 256) {
      throw new ToolInputError('header names must be at most 256 characters', `headers.${name.slice(0, 32)}`);
    }
    if (typeof rawValue !== 'string' || rawValue.length > 8192) {
      throw new ToolInputError(`headers.${name} must be a string of at most 8192 characters`, `headers.${name}`);
    }
    try {
      assertSafeHeaderName(name, `headers.${name}`);
      assertSafeHeaderValue(rawValue, `headers.${name}`);
      headers.set(name.toLowerCase(), { name, value: rawValue });
    } catch (error) {
      validationFindings.push({
        header: name,
        ...errorPayload(error),
      });
    }
  }

  return { headers, validationFindings };
}

function auditHeaders(rawArgs) {
  const args = assertArgumentsObject(rawArgs);
  assertOnlyKeys(args, ['headers', 'csp', 'setCookie']);
  requireOne(args, ['headers', 'csp', 'setCookie']);

  const explicitCsp = optionalString(args, 'csp', { minLength: 1, maxLength: 8192 });
  const headerInput = args.headers === undefined ? { headers: new Map(), validationFindings: [] } : headerRecordFromInput(args.headers);
  const headers = headerInput.headers;
  const validationFindings = [...headerInput.validationFindings];

  const baseline = buildSecurityHeaders();
  const missingRecommendedHeaders = Object.keys(baseline).filter((name) => !headers.has(name.toLowerCase()));

  const cspHeader = explicitCsp ?? headers.get('content-security-policy')?.value;
  let cspAudit = null;
  if (cspHeader !== undefined) {
    try {
      cspAudit = auditCsp(cspHeader);
    } catch (error) {
      validationFindings.push({ header: 'Content-Security-Policy', ...errorPayload(error) });
    }
  }

  let setCookieInputs = [];
  if (args.setCookie !== undefined) {
    setCookieInputs = Array.isArray(args.setCookie)
      ? stringArray(args.setCookie, { label: 'setCookie', maxItems: 20, maxLength: 8192, minLength: 1 })
      : [stringValue(args.setCookie, { minLength: 1, maxLength: 8192, label: 'setCookie' })];
  } else if (headers.has('set-cookie')) {
    setCookieInputs = [headers.get('set-cookie').value];
  }

  const cookieAudits = [];
  for (const setCookie of setCookieInputs) {
    try {
      const audit = auditSetCookie(setCookie);
      const { value, ...withoutValue } = audit;
      cookieAudits.push({
        ...withoutValue,
        valueLength: typeof value === 'string' ? value.length : 0,
        valueRedacted: true,
      });
    } catch (error) {
      validationFindings.push({ header: 'Set-Cookie', ...errorPayload(error) });
    }
  }

  const cspOk = cspAudit === null || cspAudit.ok === true;
  const cookiesOk = cookieAudits.every((audit) => audit.ok === true);
  const ok = validationFindings.length === 0 && missingRecommendedHeaders.length === 0 && cspOk && cookiesOk;

  return {
    ok,
    missingRecommendedHeaders,
    validationFindings,
    cspAudit,
    cookieAudits,
    recommendedHeaders: baseline,
    summary: {
      headersSupplied: headers.size,
      setCookieAudited: cookieAudits.length,
      cspAudited: cspAudit !== null,
    },
  };
}

function redirectOptions(args) {
  const options = {};
  const assign = (key, value) => {
    if (value !== undefined) options[key] = value;
  };

  assign('allowedOrigins', optionalStringOrArray(args, 'allowedOrigins', { maxItems: 32, maxLength: 512 }));
  assign('allowedHosts', optionalStringOrArray(args, 'allowedHosts', { maxItems: 32, maxLength: 512 }));
  assign('allowSubdomains', optionalBoolean(args, 'allowSubdomains'));
  assign('allowUserinfo', optionalBoolean(args, 'allowUserinfo'));
  assign('allowIpLiterals', optionalBoolean(args, 'allowIpLiterals'));
  assign('allowQuery', optionalBoolean(args, 'allowQuery'));
  assign('allowHash', optionalBoolean(args, 'allowHash'));
  assign('normalizeDotSegments', optionalBoolean(args, 'normalizeDotSegments'));
  assign('blockedPaths', optionalStringOrArray(args, 'blockedPaths', { maxItems: 64, maxLength: 1024 }));
  assign('fallback', optionalString(args, 'fallback', { minLength: 1, maxLength: 2048 }));
  assign('maxLength', optionalInteger(args, 'maxLength', { min: 1, max: 4096 }));
  assign('maxDecodeLayers', optionalInteger(args, 'maxDecodeLayers', { min: 1, max: 16 }));

  if (args.allowProtocols !== undefined) {
    const raw = args.allowProtocols;
    const values = typeof raw === 'string' ? [raw] : raw;
    const list = stringArray(values, { label: 'allowProtocols', maxItems: 4, maxLength: 16, minLength: 1 });
    for (const protocol of list) {
      if (!['http', 'http:', 'https', 'https:'].includes(protocol)) {
        throw new ToolInputError('allowProtocols entries must be http or https', 'allowProtocols');
      }
    }
    options.allowProtocols = typeof raw === 'string' ? raw : list;
  }

  return options;
}

function auditRedirect(rawArgs) {
  const args = assertArgumentsObject(rawArgs);
  assertOnlyKeys(args, [
    'target',
    'allowedOrigins',
    'allowedHosts',
    'allowSubdomains',
    'allowProtocols',
    'allowUserinfo',
    'allowIpLiterals',
    'allowQuery',
    'allowHash',
    'normalizeDotSegments',
    'blockedPaths',
    'fallback',
    'maxLength',
    'maxDecodeLayers',
  ]);
  const target = requiredString(args, 'target', { maxLength: 4096 });
  const options = redirectOptions(args);

  try {
    const result = parseRedirectLocation(target, options);
    const { input: _input, ...location } = result;
    return {
      ok: result.safe,
      safe: result.safe,
      targetLength: target.length,
      location,
    };
  } catch (error) {
    throw new ToolInputError(`invalid redirect policy: ${errorPayload(error).reason}`, 'redirectOptions');
  }
}

const ENV_TYPES = new Set([
  'string',
  'str',
  'secret',
  'bool',
  'int',
  'num',
  'port',
  'url',
  'enum',
  'json',
  'csv',
  'durationMs',
]);

function envSchemaValidator(key, rawSpec) {
  let spec = rawSpec;
  if (typeof spec === 'string') spec = { type: spec };
  if (!isPlainObject(spec)) {
    throw new ToolInputError(`schema.${key} must be a type string or an object`, `schema.${key}`);
  }
  assertOnlyKeys(spec, [
    'type',
    'optional',
    'minLength',
    'maxLength',
    'allowEmpty',
    'trim',
    'multiline',
    'min',
    'max',
    'requireHttps',
    'disallowCredentials',
    'allowedProtocols',
    'allowedHosts',
    'values',
    'caseSensitive',
    'maxDepth',
    'unique',
    'minItems',
    'maxItems',
  ], `schema.${key}`);

  const type = enumValue(spec.type, [...ENV_TYPES], `schema.${key}.type`);
  let validator;
  if (type === 'string' || type === 'str') {
    validator = t.str({
      minLength: optionalInteger(spec, 'minLength', { min: 0, max: 65536 }),
      maxLength: optionalInteger(spec, 'maxLength', { min: 1, max: 65536 }),
      allowEmpty: optionalBoolean(spec, 'allowEmpty'),
      trim: optionalBoolean(spec, 'trim'),
      multiline: optionalBoolean(spec, 'multiline'),
    });
  } else if (type === 'secret') {
    validator = t.secret({
      minLength: optionalInteger(spec, 'minLength', { min: 1, max: 65536 }),
      maxLength: optionalInteger(spec, 'maxLength', { min: 1, max: 65536 }),
    });
  } else if (type === 'bool') {
    validator = t.bool();
  } else if (type === 'int') {
    validator = t.int({
      min: optionalInteger(spec, 'min', { min: Number.MIN_SAFE_INTEGER, max: Number.MAX_SAFE_INTEGER }),
      max: optionalInteger(spec, 'max', { min: Number.MIN_SAFE_INTEGER, max: Number.MAX_SAFE_INTEGER }),
    });
  } else if (type === 'num') {
    for (const bound of ['min', 'max']) {
      if (spec[bound] !== undefined && (typeof spec[bound] !== 'number' || !Number.isFinite(spec[bound]))) {
        throw new ToolInputError(`schema.${key}.${bound} must be a finite number`, `schema.${key}.${bound}`);
      }
    }
    validator = t.num({
      min: spec.min,
      max: spec.max,
    });
  } else if (type === 'port') {
    validator = t.port();
  } else if (type === 'url') {
    const allowedProtocols = optionalStringArray(spec, 'allowedProtocols', { maxItems: 10, maxLength: 32, minLength: 2 });
    if (allowedProtocols !== undefined) {
      for (const protocol of allowedProtocols) {
        if (!/^[a-z][a-z0-9+.-]*:$/i.test(protocol)) {
          throw new ToolInputError(`schema.${key}.allowedProtocols entries must end with a colon`, `schema.${key}.allowedProtocols`);
        }
      }
    }
    validator = t.url({
      requireHttps: optionalBoolean(spec, 'requireHttps'),
      disallowCredentials: optionalBoolean(spec, 'disallowCredentials'),
      allowedProtocols,
      allowedHosts: optionalStringArray(spec, 'allowedHosts', { maxItems: 64, maxLength: 253, minLength: 1 }),
    });
  } else if (type === 'enum') {
    const values = stringArray(spec.values, { label: `schema.${key}.values`, maxItems: 100, maxLength: 256, minLength: 1 });
    validator = t.enum(values, { caseSensitive: optionalBoolean(spec, 'caseSensitive') });
  } else if (type === 'json') {
    validator = t.json({
      maxDepth: optionalInteger(spec, 'maxDepth', { min: 1, max: 64 }),
      multiline: optionalBoolean(spec, 'multiline'),
    });
  } else if (type === 'csv') {
    validator = t.csv({
      trim: optionalBoolean(spec, 'trim'),
      allowEmpty: optionalBoolean(spec, 'allowEmpty'),
      unique: optionalBoolean(spec, 'unique'),
      minItems: optionalInteger(spec, 'minItems', { min: 0, max: 1000 }),
      maxItems: optionalInteger(spec, 'maxItems', { min: 1, max: 1000 }),
    });
  } else {
    validator = t.durationMs({
      min: optionalInteger(spec, 'min', { min: 0, max: Number.MAX_SAFE_INTEGER }),
      max: optionalInteger(spec, 'max', { min: 0, max: Number.MAX_SAFE_INTEGER }),
    });
  }

  return optionalBoolean(spec, 'optional') === true ? validator.optional() : validator;
}

function buildEnvSchema(rawSchema) {
  if (rawSchema === undefined) return undefined;
  if (!isPlainObject(rawSchema)) {
    throw new ToolInputError('schema must be an object mapping environment keys to validator specifications', 'schema');
  }
  const entries = Object.entries(rawSchema);
  if (entries.length > 100) {
    throw new ToolInputError('schema must contain at most 100 keys', 'schema');
  }
  const schema = {};
  for (const [key, rawSpec] of entries) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) || key.length > 256) {
      throw new ToolInputError(`schema key "${key}" is not a safe environment variable name`, 'schema');
    }
    schema[key] = envSchemaValidator(key, rawSpec);
  }
  return schema;
}

function auditEnv(rawArgs) {
  const args = assertArgumentsObject(rawArgs);
  assertOnlyKeys(args, [
    'dotenv',
    'schema',
    'maxBytes',
    'maxEntries',
    'maxKeyLength',
    'maxValueLength',
    'onDuplicate',
  ]);
  const dotenv = requiredString(args, 'dotenv', { maxLength: 1024 * 1024 });
  const parseOptions = {
    maxBytes: optionalInteger(args, 'maxBytes', { min: 1, max: 1024 * 1024 }),
    maxEntries: optionalInteger(args, 'maxEntries', { min: 1, max: 1000 }),
    maxKeyLength: optionalInteger(args, 'maxKeyLength', { min: 1, max: 256 }),
    maxValueLength: optionalInteger(args, 'maxValueLength', { min: 1, max: 65536 }),
    onDuplicate: optionalEnum(args, 'onDuplicate', ['error', 'first', 'last']),
  };
  for (const key of Object.keys(parseOptions)) {
    if (parseOptions[key] === undefined) delete parseOptions[key];
  }

  const schema = buildEnvSchema(args.schema);
  let parsed;
  try {
    parsed = parseDotEnv(dotenv, parseOptions);
  } catch (error) {
    return auditFailure(error, {
      parse: { ok: false },
      validation: null,
      findings: [],
      entries: [],
    });
  }

  const entries = Object.entries(parsed).map(([key, value]) => {
    const secretish = /(?:secret|token|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|credential|bearer)/i.test(key);
    return {
      key,
      valueLength: value.length,
      empty: value.length === 0,
      secretish,
    };
  });

  const findings = [];
  for (const entry of entries) {
    if (entry.secretish) {
      findings.push({
        code: 'ENVCAGE_AUDIT_PLAINTEXT_SECRET',
        severity: 'medium',
        key: entry.key,
        message: 'Secret-like values in dotenv text are plaintext and must be protected by file permissions or a secret manager.',
      });
      if (entry.valueLength > 0 && entry.valueLength < 16) {
        findings.push({
          code: 'ENVCAGE_AUDIT_WEAK_SECRET_LENGTH',
          severity: 'high',
          key: entry.key,
          message: 'Secret-like value is shorter than 16 characters.',
        });
      }
    }
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(entry.key)) {
      findings.push({
        code: 'ENVCAGE_AUDIT_UNUSUAL_KEY',
        severity: 'low',
        key: entry.key,
        message: 'Environment key is not a conventional portable shell identifier.',
      });
    }
  }

  let validation = null;
  if (schema !== undefined) {
    try {
      defineEnv(schema, parsed, {
        maxValueLength: parseOptions.maxValueLength,
      });
      validation = { ok: true, issues: [] };
    } catch (error) {
      validation = {
        ok: false,
        error: errorPayload(error),
        issues: Array.isArray(error.issues)
          ? error.issues.map((issue) => ({
              key: issue.key ?? null,
              code: issue.code,
              reason: issue.reason,
              line: issue.line,
            }))
          : [],
      };
    }
  }

  const hasHighFinding = findings.some((finding) => finding.severity === 'high' || finding.severity === 'critical');
  return {
    ok: validation?.ok !== false && !hasHighFinding,
    parse: {
      ok: true,
      entryCount: entries.length,
    },
    validation,
    findings,
    entries,
  };
}

function cookieSerializeOptions(rawOptions) {
  if (rawOptions === undefined) return {};
  if (!isPlainObject(rawOptions)) throw new ToolInputError('options must be an object', 'options');
  assertOnlyKeys(rawOptions, [
    'domain',
    'path',
    'maxAge',
    'httpOnly',
    'secure',
    'sameSite',
    'partitioned',
    'encodeValue',
    'strictPercentEncoding',
    'maxValueBytes',
    'maxSerializedBytes',
    'allowIpLiteral',
    'additionalPublicSuffixes',
  ], 'options');
  const options = {
    domain: optionalString(rawOptions, 'domain', { minLength: 1, maxLength: 253 }),
    path: optionalString(rawOptions, 'path', { minLength: 1, maxLength: 1024 }),
    maxAge: optionalInteger(rawOptions, 'maxAge', { min: 0, max: 34560000 }),
    httpOnly: optionalBoolean(rawOptions, 'httpOnly'),
    secure: optionalBoolean(rawOptions, 'secure'),
    sameSite: optionalEnum(rawOptions, 'sameSite', ['strict', 'lax', 'none', 'Strict', 'Lax', 'None']),
    partitioned: optionalBoolean(rawOptions, 'partitioned'),
    encodeValue: optionalBoolean(rawOptions, 'encodeValue'),
    strictPercentEncoding: optionalBoolean(rawOptions, 'strictPercentEncoding'),
    maxValueBytes: optionalInteger(rawOptions, 'maxValueBytes', { min: 1, max: 4096 }),
    maxSerializedBytes: optionalInteger(rawOptions, 'maxSerializedBytes', { min: 1, max: 4096 }),
    allowIpLiteral: optionalBoolean(rawOptions, 'allowIpLiteral'),
    additionalPublicSuffixes: optionalStringArray(rawOptions, 'additionalPublicSuffixes', { maxItems: 64, maxLength: 253, minLength: 1 }),
  };
  for (const key of Object.keys(options)) if (options[key] === undefined) delete options[key];
  return options;
}

function cookieParseOptions(rawOptions) {
  if (rawOptions === undefined) return {};
  if (!isPlainObject(rawOptions)) throw new ToolInputError('parseOptions must be an object', 'parseOptions');
  assertOnlyKeys(rawOptions, [
    'maxHeaderBytes',
    'maxCookies',
    'maxCookieBytes',
    'duplicatePolicy',
    'decodeValues',
    'strictPercentEncoding',
  ], 'parseOptions');
  const options = {
    maxHeaderBytes: optionalInteger(rawOptions, 'maxHeaderBytes', { min: 1, max: 16384 }),
    maxCookies: optionalInteger(rawOptions, 'maxCookies', { min: 1, max: 100 }),
    maxCookieBytes: optionalInteger(rawOptions, 'maxCookieBytes', { min: 1, max: 4096 }),
    duplicatePolicy: optionalEnum(rawOptions, 'duplicatePolicy', ['reject', 'first', 'last']),
    decodeValues: optionalBoolean(rawOptions, 'decodeValues'),
    strictPercentEncoding: optionalBoolean(rawOptions, 'strictPercentEncoding'),
  };
  for (const key of Object.keys(options)) if (options[key] === undefined) delete options[key];
  return options;
}

function auditCookie(rawArgs) {
  const args = assertArgumentsObject(rawArgs);
  assertOnlyKeys(args, ['mode', 'header', 'name', 'value', 'options', 'parseOptions']);
  const mode = enumValue(args.mode, ['parse', 'serialize'], 'mode');

  if (mode === 'parse') {
    if (args.name !== undefined || args.value !== undefined || args.options !== undefined) {
      throw new ToolInputError('parse mode accepts only header and parseOptions', 'mode');
    }
    const header = requiredString(args, 'header', { maxLength: 16384 });
    const options = cookieParseOptions(args.parseOptions);
    try {
      const parsed = parseCookieHeader(header, options);
      const cookies = Object.entries(parsed).map(([name, value]) => ({
        name,
        valueLength: value.length,
        empty: value.length === 0,
      }));
      return {
        ok: true,
        mode,
        cookieCount: cookies.length,
        cookies,
        valuesRedacted: true,
      };
    } catch (error) {
      return auditFailure(error, { mode });
    }
  }

  if (args.header !== undefined || args.parseOptions !== undefined) {
    throw new ToolInputError('serialize mode accepts only name, value and options', 'mode');
  }
  const name = requiredString(args, 'name', { maxLength: 256 });
  const value = requiredString(args, 'value', { minLength: 0, maxLength: 4096 });
  const options = cookieSerializeOptions(args.options);
  try {
    const serialized = serializeCookie(name, value, options);
    return {
      ok: true,
      mode,
      serialized,
      serializedBytes: Buffer.byteLength(serialized, 'utf8'),
    };
  } catch (error) {
    return auditFailure(error, { mode });
  }
}

function zipOptions(rawOptions) {
  if (rawOptions === undefined) return {};
  if (!isPlainObject(rawOptions)) throw new ToolInputError('options must be an object', 'options');
  assertOnlyKeys(rawOptions, [
    'maxEntries',
    'maxEntryUncompressedBytes',
    'maxTotalUncompressedBytes',
    'maxCompressionRatio',
    'maxArchiveBytes',
    'maxDepth',
    'maxPathLength',
    'allowSymlinks',
    'allowSpecialFiles',
    'allowSuidSgid',
    'allowEncrypted',
    'allowPrototypePollutingNames',
    'caseInsensitiveDuplicates',
    'rejectPolyglot',
  ], 'options');
  const options = {
    maxEntries: optionalInteger(rawOptions, 'maxEntries', { min: 1, max: 10000 }),
    maxEntryUncompressedBytes: optionalInteger(rawOptions, 'maxEntryUncompressedBytes', { min: 1, max: 64 * 1024 * 1024 }),
    maxTotalUncompressedBytes: optionalInteger(rawOptions, 'maxTotalUncompressedBytes', { min: 1, max: 256 * 1024 * 1024 }),
    maxCompressionRatio: optionalInteger(rawOptions, 'maxCompressionRatio', { min: 1, max: 10000 }),
    maxArchiveBytes: optionalInteger(rawOptions, 'maxArchiveBytes', { min: 1, max: 1024 * 1024 }),
    maxDepth: optionalInteger(rawOptions, 'maxDepth', { min: 1, max: 64 }),
    maxPathLength: optionalInteger(rawOptions, 'maxPathLength', { min: 1, max: 4096 }),
    allowSymlinks: optionalBoolean(rawOptions, 'allowSymlinks'),
    allowSpecialFiles: optionalBoolean(rawOptions, 'allowSpecialFiles'),
    allowSuidSgid: optionalBoolean(rawOptions, 'allowSuidSgid'),
    allowEncrypted: optionalBoolean(rawOptions, 'allowEncrypted'),
    allowPrototypePollutingNames: optionalBoolean(rawOptions, 'allowPrototypePollutingNames'),
    caseInsensitiveDuplicates: optionalBoolean(rawOptions, 'caseInsensitiveDuplicates'),
    rejectPolyglot: optionalBoolean(rawOptions, 'rejectPolyglot'),
  };
  for (const key of Object.keys(options)) if (options[key] === undefined) delete options[key];
  return options;
}

function decodeBase64Archive(input) {
  if (input.length > MAX_BASE64_ARCHIVE_CHARS) {
    throw new ToolInputError(`archiveBase64 must be at most ${MAX_BASE64_ARCHIVE_CHARS} characters`, 'archiveBase64');
  }
  if (input.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(input)) {
    throw new ToolInputError('archiveBase64 must be canonical padded base64 without whitespace', 'archiveBase64');
  }
  const decoded = Buffer.from(input, 'base64');
  if (decoded.length > 1024 * 1024) {
    throw new ToolInputError('decoded archive must be at most 1048576 bytes', 'archiveBase64');
  }
  if (decoded.toString('base64') !== input) {
    throw new ToolInputError('archiveBase64 is not canonical base64', 'archiveBase64');
  }
  return decoded;
}

function auditZipEntries(rawArgs) {
  const args = assertArgumentsObject(rawArgs);
  assertOnlyKeys(args, ['archiveBase64', 'options']);
  const input = requiredString(args, 'archiveBase64', { maxLength: MAX_BASE64_ARCHIVE_CHARS });
  const archive = decodeBase64Archive(input);
  const options = zipOptions(args.options);

  try {
    const report = inspectZipBuffer(archive, options);
    const entries = report.entries.slice(0, MAX_ZIP_ENTRIES_RETURNED).map((entry) => ({
      index: entry.index,
      name: entry.name,
      normalizedName: entry.normalizedName,
      directory: entry.directory,
      encrypted: entry.encrypted,
      compressionMethodName: entry.compressionMethodName,
      compressedSize: entry.compressedSize,
      uncompressedSize: entry.uncompressedSize,
      compressionRatio: entry.compressionRatio,
      unixFileType: entry.unixFileType,
      invalidEncoding: entry.invalidEncoding,
    }));
    return {
      ok: report.safe,
      safe: report.safe,
      findings: report.findings,
      totals: report.totals,
      entries,
      entriesReturned: entries.length,
      entriesTruncated: report.entries.length > entries.length,
    };
  } catch (error) {
    return auditFailure(error);
  }
}

function piiOptions(rawPii) {
  if (rawPii === undefined) return undefined;
  if (!isPlainObject(rawPii)) throw new ToolInputError('pii must be an object', 'pii');
  assertOnlyKeys(rawPii, ['email', 'luhnCard', 'ssn', 'ipv4'], 'pii');
  const pii = {
    email: optionalBoolean(rawPii, 'email'),
    luhnCard: optionalBoolean(rawPii, 'luhnCard'),
    ssn: optionalBoolean(rawPii, 'ssn'),
    ipv4: optionalBoolean(rawPii, 'ipv4'),
  };
  for (const key of Object.keys(pii)) if (pii[key] === undefined) delete pii[key];
  return pii;
}

function redactPaths(rawValue) {
  if (rawValue === undefined) return undefined;
  if (!Array.isArray(rawValue) || rawValue.length > 100) {
    throw new ToolInputError('redactPaths must be an array with at most 100 entries', 'redactPaths');
  }
  return rawValue.map((entry, index) => {
    if (typeof entry === 'string') return stringValue(entry, { minLength: 1, maxLength: 1024, label: `redactPaths[${index}]` });
    return stringArray(entry, { label: `redactPaths[${index}]`, maxItems: 32, maxLength: 256, minLength: 1 });
  });
}

function redactLog(rawArgs) {
  const args = assertArgumentsObject(rawArgs);
  assertOnlyKeys(args, [
    'text',
    'record',
    'mode',
    'maxLength',
    'extraSecrets',
    'pii',
    'maxDepth',
    'maxKeys',
    'maxArrayLength',
    'maxNodes',
    'sensitiveKeys',
    'redactPaths',
  ]);

  const hasText = args.text !== undefined;
  const hasRecord = args.record !== undefined;
  if (hasText === hasRecord) {
    throw new ToolInputError('exactly one of text or record is required', 'text');
  }

  const shared = {
    extraSecrets: optionalStringArray(args, 'extraSecrets', { maxItems: 64, maxLength: 1024, minLength: 1 }),
    pii: piiOptions(args.pii),
  };
  const lineOptions = {
    mode: optionalEnum(args, 'mode', ['escape', 'strip']),
    maxLength: optionalInteger(args, 'maxLength', { min: 1, max: 8192 }),
  };
  for (const key of Object.keys(lineOptions)) if (lineOptions[key] === undefined) delete lineOptions[key];
  for (const key of Object.keys(shared)) if (shared[key] === undefined) delete shared[key];

  try {
    if (hasText) {
      const text = stringValue(args.text, { maxLength: 262144, label: 'text' });
      const sanitized = sanitizeLogLine(text, lineOptions);
      const redacted = redactSecrets(sanitized, shared);
      return {
        ok: true,
        kind: 'text',
        redacted,
        inputLength: text.length,
        outputLength: redacted.length,
      };
    }

    const serializedSize = JSON.stringify(args.record)?.length ?? 0;
    if (serializedSize > 262144) {
      throw new ToolInputError('record must serialize to at most 262144 characters', 'record');
    }
    const recordOptions = {
      ...lineOptions,
      ...shared,
      maxDepth: optionalInteger(args, 'maxDepth', { min: 1, max: 32 }),
      maxKeys: optionalInteger(args, 'maxKeys', { min: 1, max: 1000 }),
      maxArrayLength: optionalInteger(args, 'maxArrayLength', { min: 1, max: 1000 }),
      maxNodes: optionalInteger(args, 'maxNodes', { min: 1, max: 5000 }),
      sensitiveKeys: optionalStringArray(args, 'sensitiveKeys', { maxItems: 100, maxLength: 256, minLength: 1 }),
      redactPaths: redactPaths(args.redactPaths),
    };
    for (const key of Object.keys(recordOptions)) if (recordOptions[key] === undefined) delete recordOptions[key];
    const redacted = sanitizeLogRecord(args.record, recordOptions);
    return {
      ok: true,
      kind: 'record',
      redacted,
    };
  } catch (error) {
    if (error instanceof ToolInputError) throw error;
    return auditFailure(error);
  }
}

function corsPolicyInput(rawPolicy) {
  if (rawPolicy === undefined) return {};
  if (!isPlainObject(rawPolicy)) throw new ToolInputError('policy must be an object', 'policy');
  assertOnlyKeys(rawPolicy, [
    'allowedOrigins',
    'credentials',
    'methods',
    'allowedHeaders',
    'exposeHeaders',
    'maxAge',
    'allowNullOrigin',
    'allowHttpLocalhost',
    'multiLevelSubdomain',
    'allowPrivateNetwork',
    'rejectDisallowedPreflight',
    'maxRequestHeaders',
    'maxRequestHeadersBytes',
    'allowForbiddenHeaders',
  ], 'policy');
  const policy = {
    allowedOrigins: optionalStringOrArray(rawPolicy, 'allowedOrigins', { maxItems: 64, maxLength: 512 }),
    credentials: optionalBoolean(rawPolicy, 'credentials'),
    methods: optionalStringOrArray(rawPolicy, 'methods', { maxItems: 32, maxLength: 32 }),
    allowedHeaders: optionalStringOrArray(rawPolicy, 'allowedHeaders', { maxItems: 64, maxLength: 256 }),
    exposeHeaders: optionalStringOrArray(rawPolicy, 'exposeHeaders', { maxItems: 64, maxLength: 256 }),
    maxAge: optionalInteger(rawPolicy, 'maxAge', { min: 0, max: 86400 }),
    allowNullOrigin: optionalBoolean(rawPolicy, 'allowNullOrigin'),
    allowHttpLocalhost: optionalBoolean(rawPolicy, 'allowHttpLocalhost'),
    multiLevelSubdomain: optionalBoolean(rawPolicy, 'multiLevelSubdomain'),
    allowPrivateNetwork: optionalBoolean(rawPolicy, 'allowPrivateNetwork'),
    rejectDisallowedPreflight: optionalBoolean(rawPolicy, 'rejectDisallowedPreflight'),
    maxRequestHeaders: optionalInteger(rawPolicy, 'maxRequestHeaders', { min: 1, max: 100 }),
    maxRequestHeadersBytes: optionalInteger(rawPolicy, 'maxRequestHeadersBytes', { min: 1, max: 16384 }),
    allowForbiddenHeaders: optionalBoolean(rawPolicy, 'allowForbiddenHeaders'),
  };
  for (const key of Object.keys(policy)) if (policy[key] === undefined) delete policy[key];
  return policy;
}

function corsEvaluationInput(rawEvaluation) {
  if (rawEvaluation === undefined) return undefined;
  if (!isPlainObject(rawEvaluation)) throw new ToolInputError('evaluate must be an object', 'evaluate');
  assertOnlyKeys(rawEvaluation, ['method', 'origin', 'headers'], 'evaluate');
  const method = optionalString(rawEvaluation, 'method', { minLength: 1, maxLength: 32 }) ?? 'GET';
  if (!/^[A-Za-z]+$/.test(method)) {
    throw new ToolInputError('evaluate.method must contain only ASCII letters', 'evaluate.method');
  }
  const origin = optionalString(rawEvaluation, 'origin', { maxLength: 512 });
  const rawHeaders = rawEvaluation.headers === undefined ? {} : rawEvaluation.headers;
  const { headers, validationFindings } = headerRecordFromInput(rawHeaders);
  if (validationFindings.length > 0) {
    throw new ToolInputError(`evaluate.headers contains an unsafe header: ${validationFindings[0].header}`, 'evaluate.headers');
  }
  const requestHeaders = {};
  for (const { name, value } of headers.values()) requestHeaders[name.toLowerCase()] = value;
  if (origin !== undefined) requestHeaders.origin = origin;
  return {
    method: method.toUpperCase(),
    headers: requestHeaders,
  };
}

function auditCors(rawArgs) {
  const args = assertArgumentsObject(rawArgs);
  assertOnlyKeys(args, ['policy', 'evaluate']);
  const policyInput = corsPolicyInput(args.policy);
  const evaluationInput = corsEvaluationInput(args.evaluate);

  const findings = [...lintCorsPolicy(policyInput)];
  let evaluation = null;
  let policyError = null;
  try {
    const policy = createCorsPolicy(policyInput);
    if (evaluationInput !== undefined) {
      evaluation = policy.evaluate(evaluationInput);
    }
  } catch (error) {
    policyError = errorPayload(error);
  }

  const serious = findings.some((finding) => finding.severity === 'critical' || finding.severity === 'high');
  return {
    ok: !serious && policyError === null && evaluation?.allowed !== false,
    findings,
    evaluation,
    policyError,
  };
}

function jsonOptions(rawOptions) {
  if (rawOptions === undefined) return {};
  if (!isPlainObject(rawOptions)) throw new ToolInputError('options must be an object', 'options');
  assertOnlyKeys(rawOptions, [
    'maxBytes',
    'maxOutputBytes',
    'maxDepth',
    'maxKeys',
    'maxArrayLength',
    'maxNodes',
    'maxStringLength',
    'maxKeyLength',
    'duplicateKeys',
    'protoPolicy',
    'nullPrototype',
    'rejectBom',
    'rejectNulKeys',
    'rejectNulStrings',
    'rejectUnsafeIntegers',
    'rejectNumberOverflow',
  ], 'options');
  const options = {
    maxBytes: optionalInteger(rawOptions, 'maxBytes', { min: 1, max: 2 * 1024 * 1024 }),
    maxOutputBytes: optionalInteger(rawOptions, 'maxOutputBytes', { min: 1, max: 2 * 1024 * 1024 }),
    maxDepth: optionalInteger(rawOptions, 'maxDepth', { min: 1, max: 128 }),
    maxKeys: optionalInteger(rawOptions, 'maxKeys', { min: 1, max: 10000 }),
    maxArrayLength: optionalInteger(rawOptions, 'maxArrayLength', { min: 1, max: 100000 }),
    maxNodes: optionalInteger(rawOptions, 'maxNodes', { min: 1, max: 100000 }),
    maxStringLength: optionalInteger(rawOptions, 'maxStringLength', { min: 1, max: 262144 }),
    maxKeyLength: optionalInteger(rawOptions, 'maxKeyLength', { min: 1, max: 1024 }),
    duplicateKeys: optionalEnum(rawOptions, 'duplicateKeys', ['reject', 'first', 'last']),
    protoPolicy: optionalEnum(rawOptions, 'protoPolicy', ['reject', 'strip']),
    nullPrototype: optionalBoolean(rawOptions, 'nullPrototype'),
    rejectBom: optionalBoolean(rawOptions, 'rejectBom'),
    rejectNulKeys: optionalBoolean(rawOptions, 'rejectNulKeys'),
    rejectNulStrings: optionalBoolean(rawOptions, 'rejectNulStrings'),
    rejectUnsafeIntegers: optionalBoolean(rawOptions, 'rejectUnsafeIntegers'),
    rejectNumberOverflow: optionalBoolean(rawOptions, 'rejectNumberOverflow'),
  };
  for (const key of Object.keys(options)) if (options[key] === undefined) delete options[key];
  return options;
}

function auditJson(rawArgs) {
  const args = assertArgumentsObject(rawArgs);
  assertOnlyKeys(args, ['json', 'options']);
  const json = requiredString(args, 'json', { maxLength: 1024 * 1024 });
  const options = jsonOptions(args.options);
  try {
    const inspection = inspectJsonPayload(json, options);
    return {
      ok: inspection.ok,
      findings: inspection.findings,
      stats: inspection.stats,
    };
  } catch (error) {
    return auditFailure(error);
  }
}

function safeSnippetFilename(rawName) {
  const name = rawName ?? 'snippet.mjs';
  const windowsDeviceName = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(name);
  if (!/^[A-Za-z0-9._-]+$/.test(name) || name === '.' || name === '..' || name.endsWith('.') || windowsDeviceName) {
    throw new ToolInputError('filename must be a portable basename using letters, numbers, dot, underscore or hyphen', 'filename');
  }
  return name;
}

async function lintSecurityCode(rawArgs) {
  const args = assertArgumentsObject(rawArgs);
  assertOnlyKeys(args, ['code', 'filename', 'maxFileSize']);
  const code = requiredString(args, 'code', { maxLength: MAX_SNIPPET_BYTES });
  if (Buffer.byteLength(code, 'utf8') > MAX_SNIPPET_BYTES) {
    throw new ToolInputError(`code must be at most ${MAX_SNIPPET_BYTES} UTF-8 bytes`, 'code');
  }
  const filename = safeSnippetFilename(optionalString(args, 'filename', { minLength: 1, maxLength: 255 }));
  const maxFileSize = optionalInteger(args, 'maxFileSize', { min: 1, max: MAX_SNIPPET_BYTES }) ?? MAX_SNIPPET_BYTES;

  const temporaryDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'cage-mcp-lint-'));
  try {
    await fs.chmod(temporaryDirectory, 0o700);
    const snippetPath = path.join(temporaryDirectory, filename);
    await fs.writeFile(snippetPath, code, { encoding: 'utf8', mode: 0o600 });
    const result = await scan({
      root: snippetPath,
      config: {
        failOn: 'off',
        include: [],
        exclude: [],
        rules: {},
        plugins: [],
        maxFileSize,
        maxFiles: 1,
      },
    });
    const findings = limitedFindings(result.findings);
    return {
      ok: true,
      findings: findings.items,
      findingsTotal: findings.total,
      findingsTruncated: findings.truncated,
      diagnostics: result.diagnostics,
      summary: result.summary,
      scannedFilename: filename,
    };
  } finally {
    await fs.rm(temporaryDirectory, { recursive: true, force: true });
  }
}

export const TOOL_HANDLERS = Object.freeze({
  audit_path: auditPath,
  audit_headers: auditHeaders,
  audit_redirect: auditRedirect,
  audit_env: auditEnv,
  audit_cookie: auditCookie,
  audit_zip_entries: auditZipEntries,
  redact_log: redactLog,
  audit_cors: auditCors,
  audit_json: auditJson,
  lint_security_code: lintSecurityCode,
});

const objectSchema = (properties, required = []) => ({
  type: 'object',
  additionalProperties: false,
  properties,
  required,
});

const boundedString = (maxLength, minLength = 0) => ({ type: 'string', minLength, maxLength });
const stringOrList = (maxLength = 512) => ({
  anyOf: [
    boundedString(maxLength, 1),
    { type: 'array', items: boundedString(maxLength, 1), maxItems: 64 },
  ],
});
const booleanSchema = { type: 'boolean' };
const integerSchema = (minimum, maximum) => ({ type: 'integer', minimum, maximum });

export const TOOL_DEFINITIONS = Object.freeze([
  {
    name: 'audit_path',
    title: 'Audit a path for traversal outside a root',
    description: 'Resolve a caller-supplied path inside an absolute root with pathcage and report traversal, encoded traversal, symlink-independent lexical escapes, and length violations. This is lexical and does not read the filesystem.',
    inputSchema: objectSchema({
      path: boundedString(4096, 1),
      root: boundedString(4096, 1),
      decodeCheck: booleanSchema,
      maxPathLength: integerSchema(1, 8192),
    }, ['path']),
  },
  {
    name: 'audit_headers',
    title: 'Audit HTTP security headers',
    description: 'Audit HTTP headers with headersafe, including CSP and Set-Cookie analysis, CRLF validation, and comparison against a strict security header baseline.',
    inputSchema: objectSchema({
      headers: {
        type: 'object',
        additionalProperties: boundedString(8192),
        maxProperties: 100,
      },
      csp: boundedString(8192, 1),
      setCookie: {
        anyOf: [
          boundedString(8192, 1),
          { type: 'array', items: boundedString(8192, 1), maxItems: 20 },
        ],
      },
    }),
  },
  {
    name: 'audit_redirect',
    title: 'Audit a redirect target',
    description: 'Check a relative or absolute redirect target with redirectcage against explicit origin, host, protocol, query, fragment, dot-segment, and blocked-path policy.',
    inputSchema: objectSchema({
      target: boundedString(4096, 1),
      allowedOrigins: stringOrList(),
      allowedHosts: stringOrList(),
      allowSubdomains: booleanSchema,
      allowProtocols: {
        anyOf: [
          { enum: ['http', 'http:', 'https', 'https:'] },
          { type: 'array', items: { enum: ['http', 'http:', 'https', 'https:'] }, maxItems: 4 },
        ],
      },
      allowUserinfo: booleanSchema,
      allowIpLiterals: booleanSchema,
      allowQuery: booleanSchema,
      allowHash: booleanSchema,
      normalizeDotSegments: booleanSchema,
      blockedPaths: stringOrList(1024),
      fallback: boundedString(2048, 1),
      maxLength: integerSchema(1, 4096),
      maxDecodeLayers: integerSchema(1, 16),
    }, ['target']),
  },
  {
    name: 'audit_env',
    title: 'Audit dotenv content',
    description: 'Parse dotenv text with envcage without shell expansion or interpolation, optionally validate it against a small schema DSL, and report secret hygiene without returning secret values.',
    inputSchema: objectSchema({
      dotenv: boundedString(1024 * 1024, 1),
      schema: {
        type: 'object',
        additionalProperties: {
          anyOf: [
            { enum: [...ENV_TYPES] },
            { type: 'object' },
          ],
        },
        maxProperties: 100,
      },
      maxBytes: integerSchema(1, 1024 * 1024),
      maxEntries: integerSchema(1, 1000),
      maxKeyLength: integerSchema(1, 256),
      maxValueLength: integerSchema(1, 65536),
      onDuplicate: { enum: ['error', 'first', 'last'] },
    }, ['dotenv']),
  },
  {
    name: 'audit_cookie',
    title: 'Audit or serialize cookies',
    description: 'Parse a Cookie header with duplicate and percent-encoding protection, or serialize a Set-Cookie value with hardened cookiecage defaults. Parsed cookie values are redacted from the response.',
    inputSchema: objectSchema({
      mode: { enum: ['parse', 'serialize'] },
      header: boundedString(16384, 1),
      name: boundedString(256, 1),
      value: boundedString(4096),
      options: { type: 'object', additionalProperties: true },
      parseOptions: { type: 'object', additionalProperties: true },
    }, ['mode']),
  },
  {
    name: 'audit_zip_entries',
    title: 'Audit ZIP archive entries',
    description: 'Inspect a small base64 ZIP archive with zipcage and report traversal, polyglot, compression-ratio, encrypted-entry, duplicate-name, special-file, and metadata inconsistencies without extracting files.',
    inputSchema: objectSchema({
      archiveBase64: boundedString(MAX_BASE64_ARCHIVE_CHARS, 1),
      options: { type: 'object', additionalProperties: true },
    }, ['archiveBase64']),
  },
  {
    name: 'redact_log',
    title: 'Redact and sanitize logs',
    description: 'Neutralize log forging, terminal controls, secrets, credentials, sensitive object keys, optional high-precision PII patterns, and oversized structured records with logcage.',
    inputSchema: objectSchema({
      text: boundedString(262144),
      record: {},
      mode: { enum: ['escape', 'strip'] },
      maxLength: integerSchema(1, 8192),
      extraSecrets: { type: 'array', items: boundedString(1024, 1), maxItems: 64 },
      pii: {
        type: 'object',
        additionalProperties: false,
        properties: {
          email: booleanSchema,
          luhnCard: booleanSchema,
          ssn: booleanSchema,
          ipv4: booleanSchema,
        },
      },
      maxDepth: integerSchema(1, 32),
      maxKeys: integerSchema(1, 1000),
      maxArrayLength: integerSchema(1, 1000),
      maxNodes: integerSchema(1, 5000),
      sensitiveKeys: { type: 'array', items: boundedString(256, 1), maxItems: 100 },
      redactPaths: { type: 'array', maxItems: 100 },
    }),
  },
  {
    name: 'audit_cors',
    title: 'Audit a CORS policy',
    description: 'Lint a CORS configuration with corscage and optionally evaluate a bounded request shape for origin, method, preflight, credential, private-network, and header exposure decisions.',
    inputSchema: objectSchema({
      policy: { type: 'object', additionalProperties: true },
      evaluate: {
        type: 'object',
        additionalProperties: false,
        properties: {
          method: boundedString(32, 1),
          origin: boundedString(512),
          headers: { type: 'object', additionalProperties: boundedString(8192), maxProperties: 100 },
        },
      },
    }),
  },
  {
    name: 'audit_json',
    title: 'Audit a JSON payload',
    description: 'Inspect JSON text with jsoncage for duplicate keys, prototype pollution keys, depth, size, node count, unsafe numbers, invalid Unicode, BOM, and NUL hazards.',
    inputSchema: objectSchema({
      json: boundedString(1024 * 1024, 1),
      options: { type: 'object', additionalProperties: true },
    }, ['json']),
  },
  {
    name: 'lint_security_code',
    title: 'Lint source for security issues',
    description: 'Run sentinel-lint rules against one bounded source snippet in an isolated temporary file. The scanner never executes the snippet, never follows symlinks, and the temporary file is deleted before the tool returns.',
    inputSchema: objectSchema({
      code: boundedString(MAX_SNIPPET_BYTES, 1),
      filename: boundedString(255, 1),
      maxFileSize: integerSchema(1, MAX_SNIPPET_BYTES),
    }, ['code']),
  },
]);

export async function callTool(name, rawArguments) {
  const handler = TOOL_HANDLERS[name];
  if (handler === undefined) {
    const error = new ToolInputError(`unknown tool "${name}"`, 'name');
    error.unknownTool = true;
    throw error;
  }
  const args = assertArgumentsObject(rawArguments);
  assertNoDangerousKeys(args);
  return handler(args);
}
