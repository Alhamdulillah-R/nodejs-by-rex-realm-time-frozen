'use strict';

const common = require('../common');
const assert = require('assert');
const { spawn } = require('child_process');
const vm = require('vm');

const realmTime = process._realmTime;

assert.strictEqual(typeof realmTime, 'object');
assert(Object.isFrozen(realmTime));
assert.strictEqual(realmTime.releaseExternalCall, undefined);

function blockHost(delay) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, delay);
}

function onceLine(stream) {
  return new Promise((resolve) => {
    stream.once('data', (chunk) => resolve(String(chunk).trim()));
  });
}

(async () => {
  // Date and performance share the same transaction in the principal Realm.
  realmTime.enable(null);
  const principalToken = realmTime.beginExternalCall(null);
  const frozenDate = Date.now();
  const frozenDateConstructor = new Date().getTime();
  const frozenPerformance = performance.now();
  const frozenHrtime = process.hrtime.bigint();
  const frozenHrtimeTuple = process.hrtime();
  const timeOrigin = performance.timeOrigin;

  realmTime.parkExternalCall(null, principalToken);
  blockHost(50);

  assert.strictEqual(Date.now(), frozenDate);
  assert.strictEqual(new Date().getTime(), frozenDateConstructor);
  assert.strictEqual(performance.now(), frozenPerformance);
  assert.strictEqual(process.hrtime.bigint(), frozenHrtime);
  assert.deepStrictEqual(process.hrtime(), frozenHrtimeTuple);
  realmTime.commitExternalCall(null, principalToken, 6.5);
  // An identical completion is idempotent and never advances time twice.
  realmTime.commitExternalCall(null, principalToken, 6.5);
  assert.throws(
    () => realmTime.commitExternalCall(null, principalToken, 7),
    /conflicts/);

  const committedDateDelta = Date.now() - frozenDate;
  const committedPerformanceDelta = performance.now() - frozenPerformance;
  const committedHrtimeDelta =
    Number(process.hrtime.bigint() - frozenHrtime) / 1e6;
  assert(committedDateDelta >= 6,
         `unexpected Date delta: ${committedDateDelta}`);
  assert(committedPerformanceDelta >= 6.5,
         `unexpected performance delta: ${committedPerformanceDelta}`);
  assert(committedHrtimeDelta >= 6.5,
         `unexpected hrtime delta: ${committedHrtimeDelta}`);
  assert.strictEqual(performance.timeOrigin, timeOrigin);
  assert(Math.abs(Date.now() -
                  (performance.timeOrigin + performance.now())) < 100);

  // The production bridge performs loopback HTTP in native code. Receipt of
  // the request is PARK_ACK: the V8 thread is already blocked in recv() and no
  // Worker event-loop callback is needed to deliver the response.
  const controller = spawn(process.execPath, ['-e', `
    const http = require('http');
    let queryCount = 0;
    const server = http.createServer((request, response) => {
      let body = '';
      request.setEncoding('utf8');
      request.on('data', (chunk) => body += chunk);
      request.on('end', () => {
        if (request.url !== '/api/query') {
          response.statusCode = 404;
          response.end();
          return;
        }
        const query = JSON.parse(body);
        const functionDurationMs = query.method === 'phase-order' ? 40 : 4;
        setTimeout(() => {
          response.end(JSON.stringify({
            parkAck: request.headers['x-rex-realm-park-ack'],
            token: request.headers['x-rex-realm-token'],
            generation: request.headers['x-rex-realm-generation'],
            workerPid: request.headers['x-rex-realm-worker-pid'],
            controlTid: request.headers['x-rex-realm-control-tid'],
            request: query,
            functionDurationMs,
            timelineAdjustmentMs: 1,
          }));
          if (++queryCount === 2) server.close();
        }, 40);
      });
    });
    server.listen(0, '127.0.0.1', () => {
      console.log(server.address().port);
    });
  `], { stdio: ['ignore', 'pipe', 'inherit'] });
  const controllerPort = Number(await onceLine(controller.stdout));

  const requestToken = realmTime.beginExternalCall(null, 'cdp.query');
  const requestFrozen = performance.now();
  const nativeResponse = realmTime.requestExternalCall(
    null,
    requestToken,
    controllerPort,
    '/api/query',
    JSON.stringify({ method: 'Runtime.evaluate' }));
  assert.strictEqual(nativeResponse.statusCode, 200);
  assert.strictEqual(nativeResponse.hardSuspended, undefined);
  assert.strictEqual(nativeResponse.transportReleased, undefined);
  assert.strictEqual(performance.now(), requestFrozen);
  const envelope = JSON.parse(nativeResponse.body);
  assert.strictEqual(envelope.parkAck, '1');
  assert.strictEqual(envelope.token, String(requestToken));
  assert.strictEqual(envelope.generation,
                     String(realmTime.getState(null).generation));
  assert.strictEqual(envelope.workerPid, String(process.pid));
  if (process.platform === 'win32') {
    assert(Number(envelope.controlTid) > 0);
  }
  assert.strictEqual(envelope.request.method, 'Runtime.evaluate');
  realmTime.commitExternalCall(
    null,
    requestToken,
    envelope.functionDurationMs,
    envelope.timelineAdjustmentMs);
  // The V8 performance clock is fractional; the committed 4ms function plus
  // 1ms timeline adjustment may round just below 5.0 at the read boundary.
  assert(performance.now() - requestFrozen >= 4.5);

  // Go resumes the OS-suspended transport threads before returning this native
  // request. The logical clock remains frozen; commit then paces
  // functionDurationMs on the native stack and only afterward returns the
  // target scheduler to JavaScript.
  const phaseToken = realmTime.beginExternalCall(null, 'cdp.query.phase-order');
  const phaseFrozen = performance.now();
  const phaseStarted = process.hrtime.bigint();
  const phaseResponse = realmTime.requestExternalCall(
    null,
    phaseToken,
    controllerPort,
    '/api/query',
    JSON.stringify({ method: 'phase-order' }),
  );
  assert.strictEqual(phaseResponse.hardSuspended, undefined);
  assert.strictEqual(phaseResponse.transportReleased, undefined);
  assert.strictEqual(performance.now(), phaseFrozen);
  const phaseEvents = [];
  queueMicrotask(() => phaseEvents.push('microtask'));
  setTimeout(() => phaseEvents.push('timer'), 0);
  const apiBlockStarted = process.hrtime.bigint();
  realmTime.commitExternalCall(
    null,
    phaseToken,
    JSON.parse(phaseResponse.body).functionDurationMs,
    JSON.parse(phaseResponse.body).timelineAdjustmentMs,
  );
  const apiBlockElapsedMs =
    Number(process.hrtime.bigint() - apiBlockStarted) / 1e6;
  // The synchronous function-duration phase runs on the native call stack;
  // neither a microtask nor a timer may interleave before commit returns.
  assert.deepStrictEqual(phaseEvents, []);
  assert(apiBlockElapsedMs >= 39,
         `API returned before its in-place native wait: ${apiBlockElapsedMs}ms`);
  assert(apiBlockElapsedMs < 250,
         `API in-place native wait was unexpectedly long: ${apiBlockElapsedMs}ms`);
  const phaseElapsedMs =
    Number(process.hrtime.bigint() - phaseStarted) / 1e6;
  assert(phaseElapsedMs >= 35,
         `function phase returned too early: ${phaseElapsedMs}ms`);
  assert(performance.now() - phaseFrozen >= 40,
         'function phase did not advance the logical clock');
  await Promise.resolve();
  assert.deepStrictEqual(phaseEvents, ['microtask']);

  await new Promise((resolve) => controller.once('exit', resolve));

  // libuv timer deadlines use the logical loop clock. A real 60 ms park with
  // a zero-duration commit must not make a pending timer immediately expire.
  let timerFired = false;
  const timerBase = performance.now();
  const timer = new Promise((resolve) => setTimeout(() => {
    timerFired = true;
    resolve();
  }, 25));
  const timerToken = realmTime.beginExternalCall(null, 'timer-test');
  realmTime.parkExternalCall(null, timerToken);
  blockHost(60);
  assert.strictEqual(timerFired, false);
  realmTime.commitExternalCall(null, timerToken, 0);
  assert.strictEqual(timerFired, false);
  await timer;
  assert(performance.now() - timerBase >= 20);
  realmTime.disable(null);

  // A Realm owns the whole Node process.  Every context and Worker isolate
  // reads the active process clock; a second principal cannot be enabled.
  const first = vm.createContext(Object.create(null));
  const second = vm.createContext(Object.create(null));
  first.performance = performance;
  second.performance = performance;
  realmTime.enable(first);

  const firstToken = realmTime.beginExternalCall(first);
  const firstFrozen = vm.runInContext('Date.now()', first);
  const firstPerformanceFrozen = vm.runInContext('performance.now()', first);
  const secondBefore = vm.runInContext('Date.now()', second);
  const secondPerformanceBefore =
    vm.runInContext('performance.now()', second);

  realmTime.parkExternalCall(first, firstToken);
  blockHost(50);

  assert.strictEqual(vm.runInContext('Date.now()', first), firstFrozen);
  assert.strictEqual(
    vm.runInContext('performance.now()', first), firstPerformanceFrozen);
  assert.strictEqual(vm.runInContext('Date.now()', second), secondBefore);
  assert.strictEqual(
    vm.runInContext('performance.now()', second), secondPerformanceBefore);
  realmTime.commitExternalCall(first, firstToken, 2.25);
  assert.throws(
    () => realmTime.enable(second),
    /different Realm time controller/);
  assert.strictEqual(realmTime.isEnabled(second), false);

  // Nested calls are LIFO transactions and committed durations accumulate.
  const nestedBase = vm.runInContext('Date.now()', first);
  const outer = realmTime.beginExternalCall(first);
  realmTime.parkExternalCall(first, outer);
  const inner = realmTime.beginExternalCall(first);
  realmTime.parkExternalCall(first, inner);
  const nestedState = realmTime.getState(first);
  assert.strictEqual(nestedState.enabled, true);
  assert.strictEqual(nestedState.frozen, true);
  assert.strictEqual(nestedState.depth, 2);
  assert.strictEqual(nestedState.activeToken, inner);
  assert.throws(
    () => realmTime.commitExternalCall(first, outer, 1),
    /LIFO/);
  realmTime.commitExternalCall(first, inner, 2.5);
  assert.strictEqual(vm.runInContext('Date.now()', first), nestedBase);
  realmTime.commitExternalCall(first, outer, 3.5);

  const nestedDelta = vm.runInContext('Date.now()', first) - nestedBase;
  assert(nestedDelta >= 6,
         `unexpected nested Date delta: ${nestedDelta}`);

  // Aborting the outer frame discards durations committed inside it and always
  // restores a running clock.
  const abortOuter = realmTime.beginExternalCall(first);
  realmTime.parkExternalCall(first, abortOuter);
  const abortInner = realmTime.beginExternalCall(first);
  realmTime.parkExternalCall(first, abortInner);
  realmTime.commitExternalCall(first, abortInner, 100);
  realmTime.abortExternalCall(first, abortOuter);
  assert.strictEqual(realmTime.getState(first).frozen, false);

  const oldGenerationToken = realmTime.beginExternalCall(first);
  realmTime.abortExternalCall(first, oldGenerationToken);
  realmTime.disable(first);
  assert.strictEqual(realmTime.isEnabled(first), false);
  realmTime.enable(first);
  const currentGenerationToken = realmTime.beginExternalCall(first);
  assert.throws(
    () => realmTime.abortExternalCall(first, oldGenerationToken),
    /stale generation/);
  realmTime.abortExternalCall(first, currentGenerationToken);
  realmTime.disable(first);
})().then(common.mustCall());
