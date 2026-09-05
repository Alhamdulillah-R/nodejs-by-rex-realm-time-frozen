'use strict';

// RexMirror.stack.setFrameBoundary: a vm.Context that stops sharing the main
// context's V8 security token keeps host frames out of the stacks its own code
// captures, the way one browser realm stays out of another's Error.stack.

require('../common');
const assert = require('assert');
const vm = require('vm');

const probe = 'new Error("probe").stack';

// A plain vm.Context sees the whole host stack.  This is what every stock Node
// vm.Context looks like, and it is what leaks `node:vm` and host file paths
// into code running under vm.runInContext.
{
  const sandbox = vm.createContext({});

  assert.strictEqual(RexMirror.stack.getFrameBoundary(sandbox), false);

  const stack = vm.runInContext(probe, sandbox, { filename: 'blob:probe/plain' });

  assert.match(stack, /blob:probe\/plain/);
  assert.match(stack, /node:vm/);
  assert.match(stack, /test-rex-stack-boundary/);
}

// With the boundary on, only the context's own frames survive.
{
  const sandbox = vm.createContext({});

  assert.strictEqual(RexMirror.stack.setFrameBoundary(sandbox, true), true);
  assert.strictEqual(RexMirror.stack.getFrameBoundary(sandbox), true);

  const stack = vm.runInContext(probe, sandbox, { filename: 'blob:probe/bounded' });

  assert.match(stack, /blob:probe\/bounded/);
  assert.doesNotMatch(stack, /node:/);
  assert.doesNotMatch(stack, /test-rex-stack-boundary/);
}

// The context keeps its own depth: the boundary drops frames from outside, not
// frames the context itself produced.
{
  const sandbox = vm.createContext({});
  RexMirror.stack.setFrameBoundary(sandbox, true);

  const stack = vm.runInContext(
    'function inner() { return new Error("deep").stack; }\n' +
    'function outer() { return inner(); }\n' +
    'outer();',
    sandbox,
    { filename: 'blob:probe/deep' });

  assert.match(stack, /at inner \(blob:probe\/deep/);
  assert.match(stack, /at outer \(blob:probe\/deep/);
  assert.doesNotMatch(stack, /node:/);
  assert.doesNotMatch(stack, /test-rex-stack-boundary/);
}

// Errors V8 throws itself never reach a user Error constructor, so they are the
// case a JS-side wrapper cannot cover.  They are filtered too.
{
  const sandbox = vm.createContext({});
  RexMirror.stack.setFrameBoundary(sandbox, true);

  const stack = vm.runInContext(
    'try { null.x; } catch (err) { err.stack; }',
    sandbox,
    { filename: 'blob:probe/typeerror' });

  assert.match(stack, /^TypeError: /);
  assert.match(stack, /blob:probe\/typeerror/);
  assert.doesNotMatch(stack, /node:/);
  assert.doesNotMatch(stack, /test-rex-stack-boundary/);
}

// Frames are dropped while the stack is captured rather than while it is
// formatted, so code that installs its own Error.prepareStackTrace to read
// CallSite objects sees only its own frames as well.
{
  const sandbox = vm.createContext({});
  RexMirror.stack.setFrameBoundary(sandbox, true);

  const files = vm.runInContext(
    'Error.prepareStackTrace = (err, frames) =>\n' +
    '  frames.map((frame) => frame.getFileName()).join(",");\n' +
    'const captured = new Error("probe").stack;\n' +
    'Error.prepareStackTrace = undefined;\n' +
    'captured;',
    sandbox,
    { filename: 'blob:probe/prepare' });

  assert.strictEqual(files, 'blob:probe/prepare');
}

// The Error surface the context can observe is untouched: a browser reports
// stackTraceLimit 10, prepareStackTrace undefined and captureStackTrace as a
// function, and installing anything of our own there would be self-reporting.
{
  const sandbox = vm.createContext({});
  RexMirror.stack.setFrameBoundary(sandbox, true);

  const surface = vm.runInContext(
    'JSON.stringify({ limit: Error.stackTraceLimit,' +
    ' prepare: typeof Error.prepareStackTrace,' +
    ' capture: typeof Error.captureStackTrace });',
    sandbox,
    { filename: 'blob:probe/surface' });

  assert.strictEqual(
    surface,
    '{"limit":10,"prepare":"undefined","capture":"function"}');
}

// Node installs no access-check callback on contextified contexts, so taking
// the shared security token away must not change what crosses the boundary.
{
  const sandbox = { hostValue: 41, hostAdd(value) { return value + 1; } };
  vm.createContext(sandbox);
  RexMirror.stack.setFrameBoundary(sandbox, true);

  assert.strictEqual(vm.runInContext('hostAdd(hostValue)', sandbox), 42);

  vm.runInContext('globalThis.fromTarget = { n: 7 };', sandbox);
  assert.strictEqual(sandbox.fromTarget.n, 7);

  assert.throws(() => vm.runInContext('throw new Error("out");', sandbox),
                /^Error: out$/);
}

// The boundary is a switch, not a one-way door.
{
  const sandbox = vm.createContext({});

  RexMirror.stack.setFrameBoundary(sandbox, true);
  assert.strictEqual(RexMirror.stack.setFrameBoundary(sandbox, false), false);
  assert.strictEqual(RexMirror.stack.getFrameBoundary(sandbox), false);

  const stack = vm.runInContext(probe, sandbox, { filename: 'blob:probe/off' });
  assert.match(stack, /node:vm/);
}

// setFrameBoundary(context) with no second argument turns the boundary on.
{
  const sandbox = vm.createContext({});
  assert.strictEqual(RexMirror.stack.setFrameBoundary(sandbox), true);
}

// Bad arguments throw instead of quietly doing nothing.
{
  const sandbox = vm.createContext({});

  assert.throws(() => RexMirror.stack.setFrameBoundary(sandbox, 'yes'),
                { code: 'ERR_INVALID_ARG_TYPE' });
  assert.throws(() => RexMirror.stack.setFrameBoundary({}, true),
                /contextified vm object/);
  assert.throws(() => RexMirror.stack.setFrameBoundary(null, true),
                /contextified vm object/);
  assert.throws(() => RexMirror.stack.getFrameBoundary(42),
                /contextified vm object/);
}

// The facade stays frozen and hidden, like the rest of RexMirror.
{
  assert.strictEqual(Object.isFrozen(RexMirror.stack), true);
  assert.strictEqual(Object.keys(globalThis).includes('RexMirror'), false);
}
