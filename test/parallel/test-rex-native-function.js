'use strict';
// Covers RexMirror.native.createFunction / setProxySource.
require('../common');
const assert = require('node:assert');
const vm = require('node:vm');

const { createFunction, setProxySource } = globalThis.RexMirror.native;
const fnToString = Function.prototype.toString;

const ctx = vm.createContext({});
const realm = vm.runInContext('Function.prototype', ctx);
const vmGlobal = vm.runInContext('globalThis', ctx);
const VmTypeError = vm.runInContext('TypeError', ctx);

// Operation: kThrow + RemovePrototype, created in the realm of `realm`.
let seen = null;
const log = createFunction(realm, 'log', 0, function(...args) {
  seen = { self: this, args };
  return args.length;
});
assert.strictEqual(typeof log, 'function');
assert.strictEqual(log.name, 'log');
assert.strictEqual(log.length, 0);
assert.deepStrictEqual(Reflect.ownKeys(log), ['length', 'name']);
assert.strictEqual(Object.hasOwn(log, 'prototype'), false);
assert.strictEqual(Object.getPrototypeOf(log), realm);
assert.strictEqual(fnToString.call(log), 'function log() { [native code] }');
assert.strictEqual(log(1, 2, 3), 3);
assert.deepStrictEqual(seen.args, [1, 2, 3]);
assert.strictEqual(seen.self, vmGlobal);
const receiver = {};
log.call(receiver);
assert.strictEqual(seen.self, receiver);

assert.throws(() => new log(), { name: 'TypeError', message: 'log is not a constructor' });
assert.throws(() => Reflect.construct(log, []), {
  name: 'TypeError',
  message: 'function log() { [native code] } is not a constructor',
});
for (const prop of ['caller', 'arguments']) {
  assert.throws(() => log[prop], (err) => {
    assert.ok(err instanceof VmTypeError);
    return true;
  });
}

// Exceptions from the impl propagate unchanged.
const boom = new Error('boom');
const thrower = createFunction(realm, 'thrower', 1, () => { throw boom; });
assert.throws(() => thrower(), (err) => err === boom);

// Getter names keep their prefix.
const getter = createFunction(realm, 'get memory', 0, () => 42);
assert.strictEqual(getter.name, 'get memory');
assert.strictEqual(fnToString.call(getter), 'function get memory() { [native code] }');

// Constructor: has a prototype, [[Call]] and [[Construct]] go to separate impls.
const Ctor = createFunction(realm, 'Thing', 1, () => {
  throw new TypeError('Illegal constructor');
}, function(...args) {
  this.args = args;
});
assert.strictEqual(Object.hasOwn(Ctor, 'prototype'), true);
const proto = Object.create(null);
Object.defineProperty(Ctor, 'prototype', { value: proto, writable: false });
const thing = new Ctor(7);
assert.strictEqual(Object.getPrototypeOf(thing), proto);
assert.deepStrictEqual(thing.args, [7]);
assert.throws(() => Ctor(), { message: 'Illegal constructor' });
const replaced = { replaced: true };
const Factory = createFunction(realm, 'Factory', 0, () => {}, () => replaced);
assert.strictEqual(new Factory(), replaced);

// setProxySource: only a proxy whose direct target is marked reads the text.
const target = createFunction(realm, 'addEventListener', 2, () => {});
setProxySource(target, 'function addEventListener() { [native code] }');
const remote = new Proxy(target, {});
assert.strictEqual(fnToString.call(remote), 'function addEventListener() { [native code] }');
assert.strictEqual(fnToString.call(new Proxy(remote, {})), 'function () { [native code] }');
assert.strictEqual(fnToString.call(new Proxy(log, {})), 'function () { [native code] }');
assert.throws(() => Reflect.construct(remote, []), {
  message: 'function addEventListener() { [native code] } is not a constructor',
});
assert.throws(() => Reflect.get(target, 'caller', remote), (err) => {
  assert.ok(err instanceof VmTypeError);
  return true;
});
const userSource = 'function (a) { return a; }';
const userTarget = createFunction(realm, '', 1, () => {});
setProxySource(userTarget, userSource);
assert.strictEqual(fnToString.call(new Proxy(userTarget, {})), userSource);

// setProxySource on a plain function: the function itself prints the text,
// in its own realm too; unmarked functions keep their source.
function hostBuiltin(a) { return a; }
setProxySource(hostBuiltin, 'function hostBuiltin() { [native code] }');
assert.strictEqual(fnToString.call(hostBuiltin), 'function hostBuiltin() { [native code] }');
assert.strictEqual(vm.runInContext('Function.prototype.toString', ctx).call(hostBuiltin),
                   'function hostBuiltin() { [native code] }');
assert.strictEqual(fnToString.call(new Proxy(hostBuiltin, {})), 'function hostBuiltin() { [native code] }');
function unmarked(a) { return a; }
assert.strictEqual(fnToString.call(unmarked), 'function unmarked(a) { return a; }');

// Argument errors.
const expectCode = (fn) => assert.throws(fn, { code: 'ERR_INVALID_ARG_TYPE' });
expectCode(() => createFunction(1, 'x', 0, () => {}));
expectCode(() => createFunction(realm, 1, 0, () => {}));
expectCode(() => createFunction(realm, 'x', -1, () => {}));
expectCode(() => createFunction(realm, 'x', 0, null));
expectCode(() => createFunction(realm, 'x', 0, () => {}, 1));
expectCode(() => setProxySource({}, 'x'));
expectCode(() => setProxySource(() => {}, 1));
