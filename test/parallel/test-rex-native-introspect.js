'use strict';
// Covers the rex_native internal binding exposed as RexMirror.native.
require('../common');
const assert = require('node:assert');
const vm = require('node:vm');

const { native } = globalThis.RexMirror;
const { getCreationContextGlobal, getInternal } = native;

assert.ok(Object.isFrozen(native));
assert.strictEqual(Object.getPrototypeOf(native), null);

// getCreationContextGlobal
for (const primitive of [undefined, null, 1, 'str', true, Symbol('s'), 1n]) {
  assert.strictEqual(getCreationContextGlobal(primitive), undefined);
}
assert.strictEqual(getCreationContextGlobal({}), globalThis);
assert.strictEqual(getCreationContextGlobal([]), globalThis);

const ctx = vm.createContext({});
const vmGlobal = vm.runInContext('globalThis', ctx);
const vmObject = vm.runInContext('({})', ctx);
assert.strictEqual(getCreationContextGlobal(vmObject), vmGlobal);
assert.notStrictEqual(vmGlobal, globalThis);

// Proxy whose every trap counts and throws. None of the slots below may fire
// a trap, so trapCalls must stay at zero.
let trapCalls = 0;
const handler = {};
for (const trap of [
  'apply', 'construct', 'defineProperty', 'deleteProperty', 'get',
  'getOwnPropertyDescriptor', 'getPrototypeOf', 'has', 'isExtensible',
  'ownKeys', 'preventExtensions', 'set', 'setPrototypeOf',
]) {
  handler[trap] = () => {
    trapCalls++;
    throw new Error(`trap ${trap} fired`);
  };
}
const target = function() {};
const trapping = new Proxy(target, handler);
assert.strictEqual(getInternal(trapping, 'IsProxy'), true);
assert.strictEqual(getInternal(trapping, 'InternalType'), 'Proxy');
assert.strictEqual(getInternal(trapping, 'ProxyTarget'), target);
assert.strictEqual(getInternal(trapping, 'ProxyHandler'), handler);
assert.strictEqual(getInternal(trapping, 'ProxyRevoked'), false);
assert.strictEqual(getCreationContextGlobal(trapping), globalThis);
assert.strictEqual(trapCalls, 0);

// Revoked proxy.
const { proxy: revoked, revoke } = Proxy.revocable({}, {});
revoke();
assert.strictEqual(getInternal(revoked, 'IsProxy'), true);
assert.strictEqual(getInternal(revoked, 'ProxyRevoked'), true);
assert.strictEqual(getInternal(revoked, 'ProxyTarget'), null);
assert.strictEqual(getInternal(revoked, 'ProxyHandler'), null);
assert.strictEqual(getInternal(revoked, 'InternalType'), 'Proxy');

// Promise states.
const pending = new Promise(() => {});
assert.strictEqual(getInternal(pending, 'PromiseState'), 'pending');
assert.strictEqual(getInternal(pending, 'PromiseResult'), undefined);

const fulfilled = Promise.resolve(42);
assert.strictEqual(getInternal(fulfilled, 'PromiseState'), 'fulfilled');
assert.strictEqual(getInternal(fulfilled, 'PromiseResult'), 42);

const reason = new Error('boom');
const rejected = Promise.reject(reason);
rejected.catch(() => {});
assert.strictEqual(getInternal(rejected, 'PromiseState'), 'rejected');
assert.strictEqual(getInternal(rejected, 'PromiseResult'), reason);

// Bound functions.
function plain() {}
const bound = plain.bind(null);
assert.strictEqual(getInternal(bound, 'BoundTargetFunction'), plain);
assert.strictEqual(getInternal(plain, 'BoundTargetFunction'), undefined);

// Detached ArrayBuffer.
const buf = new ArrayBuffer(8);
assert.strictEqual(getInternal(buf, 'ArrayBufferDetached'), false);
const moved = buf.transfer();
assert.strictEqual(getInternal(buf, 'ArrayBufferDetached'), true);
assert.strictEqual(getInternal(moved, 'ArrayBufferDetached'), false);

// InternalType.
const cases = [
  [undefined, 'undefined'],
  [null, 'null'],
  [true, 'boolean'],
  [1, 'number'],
  ['s', 'string'],
  [Symbol('s'), 'symbol'],
  [1n, 'bigint'],
  [{}, 'Object'],
  [[], 'Array'],
  [plain, 'Function'],
  [pending, 'Promise'],
  [new ArrayBuffer(1), 'ArrayBuffer'],
  [new SharedArrayBuffer(1), 'SharedArrayBuffer'],
  [new Int8Array(1), 'TypedArray:Int8Array'],
  [new Uint8Array(1), 'TypedArray:Uint8Array'],
  [new Uint8ClampedArray(1), 'TypedArray:Uint8ClampedArray'],
  [new Int16Array(1), 'TypedArray:Int16Array'],
  [new Uint16Array(1), 'TypedArray:Uint16Array'],
  [new Int32Array(1), 'TypedArray:Int32Array'],
  [new Uint32Array(1), 'TypedArray:Uint32Array'],
  [new Float32Array(1), 'TypedArray:Float32Array'],
  [new Float64Array(1), 'TypedArray:Float64Array'],
  [new BigInt64Array(1), 'TypedArray:BigInt64Array'],
  [new BigUint64Array(1), 'TypedArray:BigUint64Array'],
  [new DataView(new ArrayBuffer(1)), 'DataView'],
  [new Map(), 'Map'],
  [new Set(), 'Set'],
  [new WeakMap(), 'WeakMap'],
  [new WeakSet(), 'WeakSet'],
  [new Date(0), 'Date'],
  [/x/, 'RegExp'],
  [new TypeError('x'), 'NativeError'],
  [Object(true), 'BooleanObject'],
  [Object(1), 'NumberObject'],
  [Object('s'), 'StringObject'],
  [Object(Symbol('s')), 'SymbolObject'],
  [Object(1n), 'BigIntObject'],
  [vmObject, 'Object'],
  [vm.runInContext('new Map()', ctx), 'Map'],
];
for (const [value, expected] of cases) {
  assert.strictEqual(getInternal(value, 'InternalType'), expected);
}

// Argument errors.
const expectCode = (fn, code) => assert.throws(fn, (err) => {
  assert.strictEqual(err.code, code);
  assert.ok(err instanceof TypeError);
  return true;
});
expectCode(() => getInternal({}), 'ERR_INVALID_ARG_TYPE');
expectCode(() => getInternal({}, 1), 'ERR_INVALID_ARG_TYPE');
expectCode(() => getInternal(1, 'PromiseState'), 'ERR_INVALID_ARG_TYPE');
expectCode(() => getInternal({}, 'PromiseResult'), 'ERR_INVALID_ARG_TYPE');
expectCode(() => getInternal({}, 'ProxyTarget'), 'ERR_INVALID_ARG_TYPE');
expectCode(() => getInternal({}, 'ProxyHandler'), 'ERR_INVALID_ARG_TYPE');
expectCode(() => getInternal({}, 'ProxyRevoked'), 'ERR_INVALID_ARG_TYPE');
expectCode(() => getInternal({}, 'BoundTargetFunction'), 'ERR_INVALID_ARG_TYPE');
expectCode(() => getInternal({}, 'ArrayBufferDetached'), 'ERR_INVALID_ARG_TYPE');
expectCode(() => getInternal({}, 'NoSuchSlot'), 'ERR_INVALID_ARG_VALUE');
expectCode(() => getInternal({}, ''), 'ERR_INVALID_ARG_VALUE');
