'use strict';

const common = require('../common');
const assert = require('assert');
const { spawn } = require('child_process');
const vm = require('vm');

const realmTime = process._realmTime;

assert.strictEqual(typeof realmTime, 'object');
assert(Object.isFrozen(realmTime));
assert.strictEqual(typeof realmTime.releaseExternalCall, 'function');

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
    let queryHeaders;
    let releaseCount = 0;
    const server = http.createServer((request, response) => {
      let body = '';
      request.setEncoding('utf8');
      request.on('data', (chunk) => body += chunk);
      request.on('end', () => {
        if (request.url === '/api/query') {
          queryHeaders = request.headers;
          setTimeout(() => response.end(JSON.stringify({
            parkAck: request.headers['x-rex-realm-park-ack'],
            token: request.headers['x-rex-realm-token'],
            generation: request.headers['x-rex-realm-generation'],
            workerPid: request.headers['x-rex-realm-worker-pid'],
            controlTid: request.headers['x-rex-realm-control-tid'],
            request: JSON.parse(body),
            functionDurationMs: 4,
            timelineAdjustmentMs: 1,
          })), 40);
          return;
        }

        const token = request.headers['x-rex-realm-token'];
        const expectedGeneration = token === undefined ? '' :
          String(BigInt(token) >> 24n);
        const controlTid = request.headers['x-rex-realm-control-tid'];
        const valid = request.method === 'POST' &&
          request.headers['x-rex-realm-release'] === '1' &&
          request.headers['x-rex-realm-park-ack'] === '1' &&
          request.headers['x-rex-realm-generation'] === expectedGeneration &&
          request.headers['x-rex-realm-worker-pid'] ===
            queryHeaders['x-rex-realm-worker-pid'] &&
          body === '{}' &&
          (process.platform !== 'win32' ||
            (Number(controlTid) > 0 &&
             controlTid === queryHeaders['x-rex-realm-control-tid']));
        response.statusCode = valid ?
          (request.url === '/api/realm-release-fail' ? 409 : 204) : 422;
        response.end();
        if (++releaseCount === 3) server.close();
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
  assert(performance.now() - requestFrozen >= 5);
  assert.strictEqual(
    realmTime.releaseExternalCall(null, requestToken, controllerPort), true);

  // Release is a second-phase Controller acknowledgement. It remains valid
  // after either terminal outcome and derives generation from the token.
  const abortedRequestToken = realmTime.beginExternalCall(
    null, 'cdp.query.abort');
  realmTime.abortExternalCall(null, abortedRequestToken);
  assert.strictEqual(
    realmTime.releaseExternalCall(null, abortedRequestToken, controllerPort),
    true);
  assert.throws(
    () => realmTime.releaseExternalCall(
      null,
      abortedRequestToken,
      controllerPort,
      '/api/realm-release-fail'),
    /HTTP status 409/);
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

  // vm contexts in one Isolate have independent controllers.
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
  assert(vm.runInContext('Date.now()', second) - secondBefore >= 30);
  assert(vm.runInContext('performance.now()', second) -
         secondPerformanceBefore >= 30);
  realmTime.commitExternalCall(first, firstToken, 2.25);

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
