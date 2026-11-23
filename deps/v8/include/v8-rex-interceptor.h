// RexMirror: receiver of the named interceptor getter call in progress.
// Kept out of v8.h so that only the embedder code that needs it includes it.

#ifndef INCLUDE_V8_REX_INTERCEPTOR_H_
#define INCLUDE_V8_REX_INTERCEPTOR_H_

#include "v8-local-handle.h"  // NOLINT(build/include_directory)
#include "v8config.h"         // NOLINT(build/include_directory)

namespace v8 {

class Isolate;
class Value;

namespace rex {

/**
 * The receiver of the named interceptor getter call in progress on this
 * thread. PropertyCallbackInfo only carries the holder, so an interceptor that
 * forwards to another object (node's contextify, forwarding to the sandbox)
 * cannot tell `new Proxy(globalThis, {}).x` or `Object.create(globalThis).x`
 * from `globalThis.x`. A global object receiver is reported as its global
 * proxy. Empty outside of a getter call.
 */
V8_EXPORT MaybeLocal<Value> CurrentInterceptorReceiver(Isolate* isolate);

}  // namespace rex
}  // namespace v8

#endif  // INCLUDE_V8_REX_INTERCEPTOR_H_
