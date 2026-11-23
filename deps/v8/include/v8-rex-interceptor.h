// RexMirror: receiver of the named interceptor getter call in progress.
// Kept out of v8.h so that only the embedder code that needs it includes it.

#ifndef INCLUDE_V8_REX_INTERCEPTOR_H_
#define INCLUDE_V8_REX_INTERCEPTOR_H_

#include "v8-local-handle.h"  // NOLINT(build/include_directory)
#include "v8config.h"         // NOLINT(build/include_directory)

namespace v8 {

class Context;
class Isolate;
class Object;
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

/**
 * The global proxy of the incumbent realm as an embedder that runs its own JS
 * between page code and a platform object sees it: the native context of the
 * innermost JavaScript frame whose context is not |host|. Frames of |host|
 * (the embedder's own code, e.g. a Proxy trap forwarding a call) are skipped,
 * as Isolate::GetIncumbentContext would otherwise report them. Empty when only
 * |host| frames are on the stack.
 */
V8_EXPORT MaybeLocal<Object> IncumbentGlobalProxy(Isolate* isolate,
                                                  Local<Context> host);

/**
 * The global object of |context|, the one behind its global proxy. It stays
 * the context's own after Context::DetachGlobal, when the global proxy has
 * moved on to a newer context, so the embedder can still look up what is
 * declared on this context's global.
 */
V8_EXPORT Local<Object> GlobalObject(Isolate* isolate, Local<Context> context);

}  // namespace rex
}  // namespace v8

#endif  // INCLUDE_V8_REX_INTERCEPTOR_H_
