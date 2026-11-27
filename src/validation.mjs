const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

export class ToolInputError extends Error {
  constructor(message, field = null) {
    super(message);
    this.name = 'ToolInputError';
    this.field = field;
  }
}

export function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function assertNoDangerousKeys(value, path = '$') {
  let nodes = 0;
  const stack = [{ current: value, currentPath: path, depth: 0 }];

  while (stack.length > 0) {
    const { current, currentPath, depth } = stack.pop();
    nodes += 1;
    if (nodes > 10000) {
      throw new ToolInputError('input contains too many nested values', currentPath);
    }
    if (depth > 64) {
      throw new ToolInputError('input is nested too deeply', currentPath);
    }
    if (Array.isArray(current)) {
      for (let index = 0; index < current.length; index += 1) {
        stack.push({
          current: current[index],
          currentPath: `${currentPath}[${index}]`,
          depth: depth + 1,
        });
      }
      continue;
    }
    if (!isPlainObject(current)) continue;

    for (const key of Object.keys(current)) {
      if (DANGEROUS_KEYS.has(key)) {
        throw new ToolInputError(`input contains forbidden prototype pollution key "${key}"`, `${currentPath}.${key}`);
      }
    }
    for (const [key, child] of Object.entries(current)) {
      stack.push({ current: child, currentPath: `${currentPath}.${key}`, depth: depth + 1 });
    }
  }
}

export function assertArgumentsObject(value) {
  if (value === undefined) return {};
  if (!isPlainObject(value)) {
    throw new ToolInputError('tool arguments must be a JSON object', 'arguments');
  }
  assertNoDangerousKeys(value);
  return value;
}

export function assertOnlyKeys(object, allowedKeys, label = 'arguments') {
  const allowed = new Set(allowedKeys);
  for (const key of Object.keys(object)) {
    if (!allowed.has(key)) {
      throw new ToolInputError(`unknown ${label} property "${key}"`, key);
    }
  }
}

export function requiredString(object, key, { minLength = 1, maxLength = 4096, label = key } = {}) {
  if (!Object.hasOwn(object, key)) {
    throw new ToolInputError(`missing required string property "${key}"`, key);
  }
  return stringValue(object[key], { minLength, maxLength, label });
}

export function optionalString(object, key, { minLength = 0, maxLength = 4096, label = key } = {}) {
  if (!Object.hasOwn(object, key) || object[key] === undefined) return undefined;
  return stringValue(object[key], { minLength, maxLength, label });
}

export function stringValue(value, { minLength = 0, maxLength = 4096, label = 'value' } = {}) {
  if (typeof value !== 'string') {
    throw new ToolInputError(`${label} must be a string`, label);
  }
  if (value.length < minLength) {
    throw new ToolInputError(`${label} must be at least ${minLength} characters`, label);
  }
  if (value.length > maxLength) {
    throw new ToolInputError(`${label} must be at most ${maxLength} characters`, label);
  }
  return value;
}

export function booleanValue(value, label) {
  if (typeof value !== 'boolean') {
    throw new ToolInputError(`${label} must be a boolean`, label);
  }
  return value;
}

export function optionalBoolean(object, key, label = key) {
  if (!Object.hasOwn(object, key) || object[key] === undefined) return undefined;
  return booleanValue(object[key], label);
}

export function integerValue(value, { min = 0, max = Number.MAX_SAFE_INTEGER, label = 'value' } = {}) {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new ToolInputError(`${label} must be an integer from ${min} through ${max}`, label);
  }
  return value;
}

export function optionalInteger(object, key, options = {}) {
  const label = options.label ?? key;
  if (!Object.hasOwn(object, key) || object[key] === undefined) return undefined;
  return integerValue(object[key], { ...options, label });
}

export function stringOrStringArray(value, { label, maxItems = 64, maxLength = 1024 }) {
  if (typeof value === 'string') {
    return stringValue(value, { minLength: 1, maxLength, label });
  }
  return stringArray(value, { label, maxItems, maxLength, minLength: 1 });
}

export function stringArray(value, { label, maxItems = 64, maxLength = 1024, minLength = 0, allowEmpty = false }) {
  if (!Array.isArray(value)) {
    throw new ToolInputError(`${label} must be an array of strings`, label);
  }
  if (!allowEmpty && value.length === 0) {
    throw new ToolInputError(`${label} must not be empty`, label);
  }
  if (value.length > maxItems) {
    throw new ToolInputError(`${label} must contain at most ${maxItems} entries`, label);
  }
  return value.map((entry, index) => stringValue(entry, {
    minLength,
    maxLength,
    label: `${label}[${index}]`,
  }));
}

export function optionalStringOrArray(object, key, options = {}) {
  if (!Object.hasOwn(object, key) || object[key] === undefined) return undefined;
  return stringOrStringArray(object[key], { label: key, ...options });
}

export function optionalStringArray(object, key, options = {}) {
  if (!Object.hasOwn(object, key) || object[key] === undefined) return undefined;
  return stringArray(object[key], { label: key, ...options });
}

export function optionalPlainObject(object, key, { maxKeys = 100, label = key } = {}) {
  if (!Object.hasOwn(object, key) || object[key] === undefined) return undefined;
  const value = object[key];
  if (!isPlainObject(value)) {
    throw new ToolInputError(`${label} must be an object`, label);
  }
  if (Object.keys(value).length > maxKeys) {
    throw new ToolInputError(`${label} must contain at most ${maxKeys} properties`, label);
  }
  return value;
}

export function enumValue(value, allowed, label) {
  if (typeof value !== 'string' || !allowed.includes(value)) {
    throw new ToolInputError(`${label} must be one of: ${allowed.join(', ')}`, label);
  }
  return value;
}

export function optionalEnum(object, key, allowed, label = key) {
  if (!Object.hasOwn(object, key) || object[key] === undefined) return undefined;
  return enumValue(object[key], allowed, label);
}

export function packageErrorPayload(error) {
  const code = typeof error?.code === 'string' ? error.code : 'UNEXPECTED_PACKAGE_ERROR';
  const reason = typeof error?.reason === 'string'
    ? error.reason
    : typeof error?.message === 'string'
      ? error.message.replace(/^[A-Z0-9_]+:\s*/i, '')
      : String(error);
  return { code, reason };
}
