# RexMirrorRealm stop-the-world virtual time

This Node.js 26.x fork provides the engine side of RexMirrorRealm's deterministic
external-call transaction. While a Realm waits for Chrome/Go, observable Node
time and the owning libuv loop clock are frozen. A successful commit advances
the timeline only by the authoritative browser function duration plus an
explicit adjustment.

This is an internal integration surface pinned to this repository's Node.js
26.x baseline. It is not a public Node.js API.

## Runtime topology

Production uses one enabled Realm per Node Worker process. Controllers remain
attached to individual Node/vm contexts, but only one controller may own a
Worker's libuv loop at a time. This prevents another Realm in that Worker from
running timers while the active Realm is parked. Isolation across Worker
processes is therefore also the scheduling boundary.

Go, Chrome, and the control plane retain real time. Suspending the complete
Worker process and virtualizing browser-side clocks are performed by the Realm
JS/Go integration, not by this Node patch.

## Observable Node clocks

When enabled, one controller consistently virtualizes:

* ECMAScript `Date`, including saved or cross-Realm references to the original
  `Date.now()` and `Date` constructor;
* `performance.now()` while keeping `performance.timeOrigin` invariant;
* `process.hrtime()`, `process.hrtime.bigint()`, and `process.uptime()`;
* libuv's loop clock, so pending timers do not expire merely because the host
  spent time waiting for Chrome.

At the outermost transaction entry, the wall and monotonic clocks are sampled
once. They remain fixed until abort or commit. Resuming rebases both clocks and
the libuv timer clock onto the committed logical duration.

## Native binding

Bootstrap installs a frozen internal binding at `process._realmTime`. Every
method accepts a context first. Pass `null` for the current Node Realm, or the
sandbox object returned by `vm.createContext()`.

```js
const clock = process._realmTime;
const context = null;

clock.enable(context);
const token = clock.beginExternalCall(context, 'Runtime.callFunctionOn');

try {
  // This native loopback request parks the frame before doing blocking I/O.
  // No callback or promise on the main JS event loop is needed for the reply.
  const response = clock.requestExternalCall(
    context,
    token,
    9334,
    '/api/query',
    JSON.stringify(request),
  );
  const envelope = JSON.parse(response.body);

  clock.commitExternalCall(
    context,
    token,
    envelope.functionDurationMs,
    envelope.timelineAdjustmentMs ?? 0,
  );
  return envelope.result;
} catch (error) {
  clock.abortExternalCall(context, token);
  throw error;
}
```

Available operations:

* `enable(context)` resets the logical clock and claims the Worker's loop;
* `disable(context)` returns to real time, clears transactions, and releases
  the loop;
* `isEnabled(context)` reports whether virtual time is enabled;
* `beginExternalCall(context, operation?)` freezes all covered clocks and
  returns a generation-scoped numeric token;
* `parkExternalCall(context, token)` records the native safe/park
  acknowledgement for an offline or otherwise precomputed operation;
* `requestExternalCall(context, token, port, path, body)` parks the active frame
  and performs a synchronous HTTP request to `127.0.0.1` on a native socket;
* `commitExternalCall(context, token, functionDurationMs,
  timelineAdjustmentMs = 0)` commits the authoritative logical duration;
* `abortExternalCall(context, token)` completes a frame without advancing it;
* `getState(context)` reports phase, generation, active operation/token,
  nesting depth, and current logical clocks.

The native request supports content-length and chunked HTTP responses, limits
the response to 64 MiB, and sends these control headers:

* `X-Rex-Realm-Park-Ack: 1`
* `X-Rex-Realm-Token`
* `X-Rex-Realm-Generation`
* `X-Rex-Realm-Worker-Pid`
* `X-Rex-Realm-Control-Tid` (Windows)

Only the loopback host is reachable through this binding. The Worker main V8
thread remains blocked in native connect/send/receive until the response is in
memory. On Windows its thread ID lets the Controller suspend every other Worker
thread while leaving only this non-JavaScript socket-drain path runnable; the
Controller resumes those threads before closing the response. JavaScript then
parses the envelope and commits before returning the result to sandbox code.

## Duration contract

`functionDurationMs` is the authoritative duration measured around the actual
browser function execution. `timelineAdjustmentMs` is an explicit signed
correction and defaults to zero. The committed delta is:

```text
functionDurationMs + timelineAdjustmentMs
```

The sum must be finite and non-negative. `cdpRoundTripMs` is diagnostic only and
must never be passed to `commitExternalCall`.

Nested frames are strict LIFO. Their committed deltas accumulate in the parent;
callers must therefore report exclusive function durations for nested calls.
Aborting the outer frame discards all accumulated nested duration. A frame must
be parked before commit.

Tokens encode the enable generation. A token from a previous enable cycle is
rejected as stale. Repeating an identical commit/abort is idempotent; repeating
the token with different outcome or duration is a conflict. A bounded history
retains the most recent 256 completions.

## Implementation map

* `src/node_realm_time.{h,cc}`: controller, transactions, native loopback IPC,
  binding, and V8 time-source wiring;
* `src/node_realm.h`, `src/node_contextify.h`: per-context controller storage;
* `src/env.cc`: V8 wall-clock callback installation;
* `src/node_perf.cc`, `src/node_process_methods.cc`: monotonic process clocks;
* `deps/uv/`: logical loop clock and timer freeze/resume;
* `deps/v8/`: embedder callback used by `Date`;
* `test/parallel/test-realm-time.js`: clock coverage, timer behavior,
  transaction invariants, vm isolation, and native HTTP IPC.

Browser event timestamps, `requestAnimationFrame`, browser performance entries,
Worker process hard-suspension, and offline record/replay belong to the
RexMirrorRealm JS/Go repository and consume this binding.
