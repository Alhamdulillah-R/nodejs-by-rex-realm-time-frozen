#include "env-inl.h"
#include "node_binding.h"
#include "node_errors.h"
#include "node_external_reference.h"
#include "node_internals.h"
#include "util-inl.h"
#include "v8-rex-interceptor.h"

#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

namespace node::rex_native {

using v8::Array;
using v8::ArrayBuffer;
using v8::Boolean;
using v8::ConstructorBehavior;
using v8::Context;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Global;
using v8::IndexedPropertyHandlerConfiguration;
using v8::Int32;
using v8::Integer;
using v8::Intercepted;
using v8::Isolate;
using v8::Local;
using v8::LocalVector;
using v8::MaybeLocal;
using v8::Name;
using v8::NamedPropertyHandlerConfiguration;
using v8::NewStringType;
using v8::Null;
using v8::Object;
using v8::ObjectTemplate;
using v8::Private;
using v8::Promise;
using v8::PropertyCallbackInfo;
using v8::PropertyDescriptor;
using v8::PropertyHandlerFlags;
using v8::Proxy;
using v8::String;
using v8::Undefined;
using v8::Value;

namespace {

// Same key as the one FunctionPrototypeToString reads in
// deps/v8/src/builtins/builtins-function.cc.
constexpr char kProxySourceKey[] = "rex.proxy_source";
// Same key as IsRexWebIdlInterface in deps/v8/src/builtins/builtins-function.cc.
constexpr char kWebIdlInterfaceKey[] = "rex.web_idl_interface";

void ReturnUtf8(const FunctionCallbackInfo<Value>& args,
                std::string_view text) {
  args.GetReturnValue().Set(
      String::NewFromUtf8(args.GetIsolate(),
                          text.data(),
                          NewStringType::kNormal,
                          static_cast<int>(text.size()))
          .ToLocalChecked());
}

// Reads the creation context through the C++ API only; no JS is executed, so
// Proxy traps and getters on `value` are never triggered.
void GetCreationContextGlobal(const FunctionCallbackInfo<Value>& args) {
  Local<Value> value = args[0];
  if (!value->IsObject()) return;

  Local<Context> context;
  if (!value.As<Object>()
           ->GetCreationContext(args.GetIsolate())
           .ToLocal(&context)) {
    args.GetReturnValue().SetNull();
    return;
  }
  args.GetReturnValue().Set(context->Global());
}

std::string_view PromiseStateName(Promise::PromiseState state) {
  if (state == Promise::PromiseState::kPending) return "pending";
  if (state == Promise::PromiseState::kFulfilled) return "fulfilled";
  return "rejected";
}

// Empty when `value` is not one of the typed array kinds below.
std::string_view TypedArrayName(Local<Value> value) {
  if (value->IsInt8Array()) return "Int8Array";
  if (value->IsUint8Array()) return "Uint8Array";
  if (value->IsUint8ClampedArray()) return "Uint8ClampedArray";
  if (value->IsInt16Array()) return "Int16Array";
  if (value->IsUint16Array()) return "Uint16Array";
  if (value->IsInt32Array()) return "Int32Array";
  if (value->IsUint32Array()) return "Uint32Array";
  if (value->IsFloat16Array()) return "Float16Array";
  if (value->IsFloat32Array()) return "Float32Array";
  if (value->IsFloat64Array()) return "Float64Array";
  if (value->IsBigInt64Array()) return "BigInt64Array";
  if (value->IsBigUint64Array()) return "BigUint64Array";
  return "";
}

std::string InternalType(Local<Value> value) {
  if (value->IsProxy()) return "Proxy";
  if (value->IsPromise()) return "Promise";
  if (value->IsFunction()) return "Function";
  if (value->IsArray()) return "Array";
  if (value->IsArrayBuffer()) return "ArrayBuffer";
  if (value->IsSharedArrayBuffer()) return "SharedArrayBuffer";
  if (std::string_view name = TypedArrayName(value); !name.empty()) {
    return "TypedArray:" + std::string(name);
  }
  if (value->IsDataView()) return "DataView";
  if (value->IsMap()) return "Map";
  if (value->IsSet()) return "Set";
  if (value->IsWeakMap()) return "WeakMap";
  if (value->IsWeakSet()) return "WeakSet";
  if (value->IsDate()) return "Date";
  if (value->IsRegExp()) return "RegExp";
  if (value->IsNativeError()) return "NativeError";
  if (value->IsBooleanObject()) return "BooleanObject";
  if (value->IsNumberObject()) return "NumberObject";
  if (value->IsStringObject()) return "StringObject";
  if (value->IsSymbolObject()) return "SymbolObject";
  if (value->IsBigIntObject()) return "BigIntObject";
  if (value->IsExternal()) return "External";
  if (value->IsObject()) return "Object";
  if (value->IsNull()) return "null";
  if (value->IsUndefined()) return "undefined";
  if (value->IsBoolean()) return "boolean";
  if (value->IsNumber()) return "number";
  if (value->IsString()) return "string";
  if (value->IsSymbol()) return "symbol";
  return "bigint";
}

void GetInternal(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Isolate* isolate = env->isolate();
  if (!args[1]->IsString()) {
    return THROW_ERR_INVALID_ARG_TYPE(env, "slot must be a string");
  }
  Utf8Value slot_utf8(isolate, args[1]);
  std::string_view slot(*slot_utf8, slot_utf8.length());
  Local<Value> value = args[0];

  if (slot == "InternalType") {
    return ReturnUtf8(args, InternalType(value));
  }
  if (slot == "IsProxy") {
    args.GetReturnValue().Set(value->IsProxy());
    return;
  }
  if (slot == "PromiseState") {
    if (!value->IsPromise()) {
      return THROW_ERR_INVALID_ARG_TYPE(
          env, "slot PromiseState requires a Promise");
    }
    return ReturnUtf8(args, PromiseStateName(value.As<Promise>()->State()));
  }
  if (slot == "PromiseResult") {
    if (!value->IsPromise()) {
      return THROW_ERR_INVALID_ARG_TYPE(
          env, "slot PromiseResult requires a Promise");
    }
    Local<Promise> promise = value.As<Promise>();
    if (promise->State() == Promise::PromiseState::kPending) return;
    args.GetReturnValue().Set(promise->Result());
    return;
  }
  if (slot == "ProxyTarget") {
    if (!value->IsProxy()) {
      return THROW_ERR_INVALID_ARG_TYPE(env,
                                        "slot ProxyTarget requires a Proxy");
    }
    args.GetReturnValue().Set(value.As<Proxy>()->GetTarget());
    return;
  }
  if (slot == "ProxyHandler") {
    if (!value->IsProxy()) {
      return THROW_ERR_INVALID_ARG_TYPE(env,
                                        "slot ProxyHandler requires a Proxy");
    }
    args.GetReturnValue().Set(value.As<Proxy>()->GetHandler());
    return;
  }
  if (slot == "ProxyRevoked") {
    if (!value->IsProxy()) {
      return THROW_ERR_INVALID_ARG_TYPE(env,
                                        "slot ProxyRevoked requires a Proxy");
    }
    args.GetReturnValue().Set(value.As<Proxy>()->IsRevoked());
    return;
  }
  if (slot == "BoundTargetFunction") {
    if (!value->IsFunction()) {
      return THROW_ERR_INVALID_ARG_TYPE(
          env, "slot BoundTargetFunction requires a Function");
    }
    args.GetReturnValue().Set(
        value.As<Function>()->GetBoundFunction());
    return;
  }
  if (slot == "ArrayBufferDetached") {
    if (!value->IsArrayBuffer()) {
      return THROW_ERR_INVALID_ARG_TYPE(
          env, "slot ArrayBufferDetached requires an ArrayBuffer");
    }
    args.GetReturnValue().Set(value.As<ArrayBuffer>()->WasDetached());
    return;
  }

  return THROW_ERR_INVALID_ARG_VALUE(
      env,
      "unknown slot \"" + std::string(slot) +
          "\"; supported: InternalType, IsProxy, PromiseState, "
          "PromiseResult, ProxyTarget, ProxyHandler, ProxyRevoked, "
          "BoundTargetFunction, ArrayBufferDetached");
}

// [[Call]] and [[Construct]] of a function made by createFunction. Data holds
// [call, construct]; the receiver is the one V8 hands to API functions, i.e.
// the global proxy for an undefined `this` and the new object for `new`.
void InvokeFunction(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = args.GetIsolate();
  Local<Context> context = isolate->GetCurrentContext();
  Local<Array> impls = args.Data().As<Array>();

  Local<Value> impl;
  if (!impls->Get(context, args.IsConstructCall() ? 1 : 0).ToLocal(&impl)) {
    return;
  }

  LocalVector<Value> argv(isolate, args.Length());
  for (int i = 0; i < args.Length(); i++) {
    argv[i] = args[i];
  }

  Local<Value> result;
  if (!impl.As<Function>()
           ->Call(context,
                  args.This(),
                  static_cast<int>(argv.size()),
                  argv.data())
           .ToLocal(&result)) {
    return;
  }
  args.GetReturnValue().Set(result);
}

// createFunction(realm, name, length, call, construct): an API function built
// from a fresh FunctionTemplate in the context that created `realm`. Without
// `construct` it is ConstructorBehavior::kThrow, which also removes the
// prototype, like a WebIDL operation.
void CreateFunction(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Isolate* isolate = env->isolate();
  if (!args[0]->IsObject()) {
    return THROW_ERR_INVALID_ARG_TYPE(env, "realm must be an object");
  }
  if (!args[1]->IsString()) {
    return THROW_ERR_INVALID_ARG_TYPE(env, "name must be a string");
  }
  if (!args[2]->IsInt32() || args[2].As<Int32>()->Value() < 0) {
    return THROW_ERR_INVALID_ARG_TYPE(env,
                                      "length must be a non-negative int32");
  }
  if (!args[3]->IsFunction()) {
    return THROW_ERR_INVALID_ARG_TYPE(env, "call must be a function");
  }
  if (!args[4]->IsUndefined() && !args[4]->IsFunction()) {
    return THROW_ERR_INVALID_ARG_TYPE(
        env, "construct must be a function or undefined");
  }

  Local<Context> context;
  if (!args[0].As<Object>()->GetCreationContext(isolate).ToLocal(&context)) {
    return THROW_ERR_INVALID_ARG_VALUE(env, "realm has no creation context");
  }

  Local<Value> impls[] = {args[3], args[4]};
  Local<Array> data = Array::New(isolate, impls, 2);
  ConstructorBehavior behavior = args[4]->IsFunction()
                                     ? ConstructorBehavior::kAllow
                                     : ConstructorBehavior::kThrow;

  Local<Function> fn;
  if (!Function::New(context,
                     InvokeFunction,
                     data,
                     args[2].As<Int32>()->Value(),
                     behavior)
           .ToLocal(&fn)) {
    return;
  }
  fn->SetName(args[1].As<String>());
  args.GetReturnValue().Set(fn);
}

// setProxySource(target, source): Function.prototype.toString on `target`
// itself (when it is a function), or on a Proxy whose direct target is
// `target`, returns `source`.
void SetProxySource(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Isolate* isolate = env->isolate();
  if (!args[0]->IsFunction()) {
    return THROW_ERR_INVALID_ARG_TYPE(env, "target must be a function");
  }
  if (!args[1]->IsString()) {
    return THROW_ERR_INVALID_ARG_TYPE(env, "source must be a string");
  }

  Local<Private> key =
      Private::ForApi(isolate, FIXED_ONE_BYTE_STRING(isolate, kProxySourceKey));
  if (args[0]
          .As<Object>()
          ->SetPrivate(env->context(), key, args[1])
          .IsNothing()) {
    return;
  }
}

// setIdlInterface(fn): mark `fn` as a Web IDL interface object (Blob / URL /
// TextEncoder ... in the sandbox). Its caller / arguments read as null, the
// same as Chrome, instead of the strict-function poison pill.
void SetIdlInterface(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Isolate* isolate = env->isolate();
  if (!args[0]->IsFunction()) {
    return THROW_ERR_INVALID_ARG_TYPE(env, "target must be a function");
  }

  Local<Private> key = Private::ForApi(
      isolate, FIXED_ONE_BYTE_STRING(isolate, kWebIdlInterfaceKey));
  if (args[0]
          .As<Object>()
          ->SetPrivate(env->context(), key, FIXED_ONE_BYTE_STRING(isolate, "1"))
          .IsNothing()) {
    return;
  }
}

/*
 * Remote objects: API objects with named + indexed interceptors that forward
 * every property operation to a JS dispatch function. The only internal field
 * holds [ref, dispatch]. Contract:
 * rex-mirror-realm/doc/native_remote_object_contract.md
 */
constexpr int kRemoteSlotField = 0;
constexpr int kRemoteFieldCount = 1;
// createRemoteObject flags: which interceptors the object gets.
constexpr int kRemoteNamed = 1;
constexpr int kRemoteIndexed = 2;
constexpr int kRemoteFlagCombinations = 4;

struct RemoteState {
  // One template per flags value, built on first use by RemoteTemplate;
  // HasInstance on them is the brand check.
  Global<FunctionTemplate> templates[kRemoteFlagCombinations];
  // remoteNotIntercepted, also the interceptor data of the template.
  Global<Object> not_intercepted;
  // RexMirror: 引擎错误回调用的 context (EnableEngineErrorHook 设置; env cleanup 时随 state 释放)
  Global<Context> error_hook_context;
};

// Built lazily at run time, not in Initialize: the binding is loaded while the
// startup snapshot is built, and C++ state does not survive deserialization.
// The map is leaked so no Global is reset after its isolate is gone.
std::mutex remote_states_mutex;
auto* remote_states =
    new std::unordered_map<Isolate*, std::unique_ptr<RemoteState>>();

void DropRemoteState(void* data) {
  std::lock_guard<std::mutex> lock(remote_states_mutex);
  remote_states->erase(static_cast<Isolate*>(data));
}

RemoteState* GetRemoteState(Environment* env) {
  Isolate* isolate = env->isolate();
  std::lock_guard<std::mutex> lock(remote_states_mutex);
  auto found = remote_states->find(isolate);
  if (found != remote_states->end()) return found->second.get();

  auto state = std::make_unique<RemoteState>();
  Local<Object> not_intercepted =
      Object::New(isolate, Null(isolate), nullptr, nullptr, 0);
  not_intercepted->SetIntegrityLevel(env->context(), v8::IntegrityLevel::kFrozen)
      .Check();
  state->not_intercepted.Reset(isolate, not_intercepted);

  RemoteState* raw = state.get();
  remote_states->emplace(isolate, std::move(state));
  env->AddCleanupHook(DropRemoteState, isolate);
  return raw;
}

Local<String> InternalizedString(Isolate* isolate, const char* text) {
  return String::NewFromUtf8(isolate, text, NewStringType::kInternalized)
      .ToLocalChecked();
}

/**
 * Calls dispatch(op, kind, ref, key, value, shouldThrow) of the remote object
 * that holds the interceptor. V8 does not hand the receiver to interceptors.
 */
template <typename T>
MaybeLocal<Value> CallDispatch(const PropertyCallbackInfo<T>& info,
                               const char* op,
                               const char* kind,
                               Local<Value> key,
                               Local<Value> value) {
  Isolate* isolate = info.GetIsolate();
  Local<Context> context = isolate->GetCurrentContext();
  Local<Object> holder = info.HolderV2();
  Local<Array> slot =
      holder->GetInternalField(kRemoteSlotField).As<Value>().As<Array>();

  Local<Value> ref;
  Local<Value> dispatch;
  if (!slot->Get(context, 0).ToLocal(&ref) ||
      !slot->Get(context, 1).ToLocal(&dispatch)) {
    return MaybeLocal<Value>();
  }

  Local<Value> argv[] = {
      InternalizedString(isolate, op),
      InternalizedString(isolate, kind),
      ref,
      key,
      value,
      Boolean::New(isolate, info.ShouldThrowOnError()),
  };
  return dispatch.As<Function>()->Call(
      context, Undefined(isolate), arraysize(argv), argv);
}

template <typename T>
bool IsNotIntercepted(const PropertyCallbackInfo<T>& info,
                      Local<Value> result) {
  return result->StrictEquals(info.Data());
}

void ThrowInvalidDispatchResult(Isolate* isolate,
                                const char* op,
                                const char* expected) {
  THROW_ERR_INVALID_RETURN_VALUE(
      isolate, "remote dispatch '%s' must return %s", op, expected);
}

Intercepted RemoteGet(const char* kind,
                      Local<Value> key,
                      const PropertyCallbackInfo<Value>& info) {
  Local<Value> result;
  if (!CallDispatch(info, "get", kind, key, Undefined(info.GetIsolate()))
           .ToLocal(&result)) {
    return Intercepted::kYes;
  }
  if (IsNotIntercepted(info, result)) return Intercepted::kNo;
  info.GetReturnValue().Set(result);
  return Intercepted::kYes;
}

// [[Set]] and [[DefineOwnProperty]]: true, false or remoteNotIntercepted.
Intercepted RemoteWrite(const char* op,
                        const char* kind,
                        Local<Value> key,
                        Local<Value> value,
                        const PropertyCallbackInfo<void>& info) {
  Local<Value> result;
  if (!CallDispatch(info, op, kind, key, value).ToLocal(&result)) {
    return Intercepted::kYes;
  }
  if (IsNotIntercepted(info, result)) return Intercepted::kNo;
  if (!result->IsBoolean()) {
    ThrowInvalidDispatchResult(
        info.GetIsolate(), op, "a boolean or remoteNotIntercepted");
    return Intercepted::kYes;
  }
  if (!result.As<Boolean>()->Value()) info.GetReturnValue().SetFalse();
  return Intercepted::kYes;
}

Intercepted RemoteQuery(const char* kind,
                        Local<Value> key,
                        const PropertyCallbackInfo<Integer>& info) {
  Local<Value> result;
  if (!CallDispatch(info, "query", kind, key, Undefined(info.GetIsolate()))
           .ToLocal(&result)) {
    return Intercepted::kYes;
  }
  if (IsNotIntercepted(info, result)) return Intercepted::kNo;
  if (!result->IsInt32()) {
    ThrowInvalidDispatchResult(info.GetIsolate(),
                               "query",
                               "an int32 attribute mask or "
                               "remoteNotIntercepted");
    return Intercepted::kYes;
  }
  info.GetReturnValue().Set(result.As<Int32>()->Value());
  return Intercepted::kYes;
}

Intercepted RemoteDelete(const char* kind,
                         Local<Value> key,
                         const PropertyCallbackInfo<Boolean>& info) {
  Local<Value> result;
  if (!CallDispatch(info, "delete", kind, key, Undefined(info.GetIsolate()))
           .ToLocal(&result)) {
    return Intercepted::kYes;
  }
  if (IsNotIntercepted(info, result)) return Intercepted::kNo;
  if (!result->IsBoolean()) {
    ThrowInvalidDispatchResult(
        info.GetIsolate(), "delete", "a boolean or remoteNotIntercepted");
    return Intercepted::kYes;
  }
  info.GetReturnValue().Set(result.As<Boolean>()->Value());
  return Intercepted::kYes;
}

Intercepted RemoteDescriptor(const char* kind,
                             Local<Value> key,
                             const PropertyCallbackInfo<Value>& info) {
  Local<Value> result;
  if (!CallDispatch(
           info, "descriptor", kind, key, Undefined(info.GetIsolate()))
           .ToLocal(&result)) {
    return Intercepted::kYes;
  }
  if (IsNotIntercepted(info, result)) return Intercepted::kNo;
  info.GetReturnValue().Set(result);
  return Intercepted::kYes;
}

Intercepted RemoteDefine(const char* kind,
                         Local<Value> key,
                         const PropertyDescriptor& desc,
                         const PropertyCallbackInfo<void>& info) {
  Isolate* isolate = info.GetIsolate();
  Local<Context> context = isolate->GetCurrentContext();
  Local<Object> fields = Object::New(isolate, Null(isolate), nullptr, nullptr, 0);

  if (desc.has_value() &&
      fields->CreateDataProperty(
              context, FIXED_ONE_BYTE_STRING(isolate, "value"), desc.value())
          .IsNothing()) {
    return Intercepted::kYes;
  }
  if (desc.has_writable() &&
      fields->CreateDataProperty(context,
                                 FIXED_ONE_BYTE_STRING(isolate, "writable"),
                                 Boolean::New(isolate, desc.writable()))
          .IsNothing()) {
    return Intercepted::kYes;
  }
  if (desc.has_get() &&
      fields->CreateDataProperty(
              context, FIXED_ONE_BYTE_STRING(isolate, "get"), desc.get())
          .IsNothing()) {
    return Intercepted::kYes;
  }
  if (desc.has_set() &&
      fields->CreateDataProperty(
              context, FIXED_ONE_BYTE_STRING(isolate, "set"), desc.set())
          .IsNothing()) {
    return Intercepted::kYes;
  }
  if (desc.has_enumerable() &&
      fields->CreateDataProperty(context,
                                 FIXED_ONE_BYTE_STRING(isolate, "enumerable"),
                                 Boolean::New(isolate, desc.enumerable()))
          .IsNothing()) {
    return Intercepted::kYes;
  }
  if (desc.has_configurable() &&
      fields->CreateDataProperty(context,
                                 FIXED_ONE_BYTE_STRING(isolate, "configurable"),
                                 Boolean::New(isolate, desc.configurable()))
          .IsNothing()) {
    return Intercepted::kYes;
  }

  return RemoteWrite("define", kind, key, fields, info);
}

void RemoteOwnKeys(const char* kind, const PropertyCallbackInfo<Array>& info) {
  Isolate* isolate = info.GetIsolate();
  Local<Value> result;
  if (!CallDispatch(info, "ownKeys", kind, Undefined(isolate), Undefined(isolate))
           .ToLocal(&result)) {
    return;
  }
  if (result->IsUndefined() || IsNotIntercepted(info, result)) return;
  if (!result->IsArray()) {
    ThrowInvalidDispatchResult(
        isolate, "ownKeys", "an array, undefined or remoteNotIntercepted");
    return;
  }
  info.GetReturnValue().Set(result.As<Array>());
}

Intercepted NamedGet(Local<Name> property,
                     const PropertyCallbackInfo<Value>& info) {
  return RemoteGet("named", property, info);
}

Intercepted NamedSet(Local<Name> property,
                     Local<Value> value,
                     const PropertyCallbackInfo<void>& info) {
  return RemoteWrite("set", "named", property, value, info);
}

Intercepted NamedQuery(Local<Name> property,
                       const PropertyCallbackInfo<Integer>& info) {
  return RemoteQuery("named", property, info);
}

Intercepted NamedDelete(Local<Name> property,
                        const PropertyCallbackInfo<Boolean>& info) {
  return RemoteDelete("named", property, info);
}

void NamedOwnKeys(const PropertyCallbackInfo<Array>& info) {
  RemoteOwnKeys("named", info);
}

Intercepted NamedDefine(Local<Name> property,
                        const PropertyDescriptor& desc,
                        const PropertyCallbackInfo<void>& info) {
  return RemoteDefine("named", property, desc, info);
}

Intercepted NamedDescriptor(Local<Name> property,
                            const PropertyCallbackInfo<Value>& info) {
  return RemoteDescriptor("named", property, info);
}

Intercepted IndexedGet(uint32_t index,
                       const PropertyCallbackInfo<Value>& info) {
  return RemoteGet(
      "indexed", Integer::NewFromUnsigned(info.GetIsolate(), index), info);
}

Intercepted IndexedSet(uint32_t index,
                       Local<Value> value,
                       const PropertyCallbackInfo<void>& info) {
  return RemoteWrite("set",
                     "indexed",
                     Integer::NewFromUnsigned(info.GetIsolate(), index),
                     value,
                     info);
}

Intercepted IndexedQuery(uint32_t index,
                         const PropertyCallbackInfo<Integer>& info) {
  return RemoteQuery(
      "indexed", Integer::NewFromUnsigned(info.GetIsolate(), index), info);
}

Intercepted IndexedDelete(uint32_t index,
                          const PropertyCallbackInfo<Boolean>& info) {
  return RemoteDelete(
      "indexed", Integer::NewFromUnsigned(info.GetIsolate(), index), info);
}

void IndexedOwnKeys(const PropertyCallbackInfo<Array>& info) {
  RemoteOwnKeys("indexed", info);
}

Intercepted IndexedDefine(uint32_t index,
                          const PropertyDescriptor& desc,
                          const PropertyCallbackInfo<void>& info) {
  return RemoteDefine(
      "indexed", Integer::NewFromUnsigned(info.GetIsolate(), index), desc, info);
}

Intercepted IndexedDescriptor(uint32_t index,
                              const PropertyCallbackInfo<Value>& info) {
  return RemoteDescriptor(
      "indexed", Integer::NewFromUnsigned(info.GetIsolate(), index), info);
}

/**
 * The FunctionTemplate whose instances are remote objects with the
 * interceptors selected by `flags`. V8 never prints its name: SetPrototype
 * gives the object a derived map, so #<X> in error messages comes from
 * Symbol.toStringTag on the prototype chain.
 */
Local<FunctionTemplate> RemoteTemplate(Isolate* isolate,
                                       RemoteState* state,
                                       int flags) {
  Global<FunctionTemplate>& cached = state->templates[flags];
  if (!cached.IsEmpty()) return cached.Get(isolate);

  Local<FunctionTemplate> tmpl = FunctionTemplate::New(isolate);
  tmpl->SetClassName(FIXED_ONE_BYTE_STRING(isolate, "RexRemoteObject"));

  Local<ObjectTemplate> instance = tmpl->InstanceTemplate();
  instance->SetInternalFieldCount(kRemoteFieldCount);
  Local<Value> not_intercepted = state->not_intercepted.Get(isolate);
  if (flags & kRemoteNamed) {
    instance->SetHandler(NamedPropertyHandlerConfiguration(
        NamedGet,
        NamedSet,
        NamedQuery,
        NamedDelete,
        NamedOwnKeys,
        NamedDefine,
        NamedDescriptor,
        not_intercepted,
        PropertyHandlerFlags::kNone));
  }
  if (flags & kRemoteIndexed) {
    instance->SetHandler(IndexedPropertyHandlerConfiguration(
        IndexedGet,
        IndexedSet,
        IndexedQuery,
        IndexedDelete,
        IndexedOwnKeys,
        IndexedDefine,
        IndexedDescriptor,
        not_intercepted,
        PropertyHandlerFlags::kNone));
  }

  cached.Reset(isolate, tmpl);
  return tmpl;
}

/**
 * createRemoteObject(realm, proto, dispatch, ref, flags): a remote object in
 * the context that created `realm`, whose [[Prototype]] is `proto`. `flags`
 * selects the interceptors (1 named, 2 indexed); with 0 the object has none
 * and `dispatch` may be undefined.
 */
void CreateRemoteObject(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Isolate* isolate = env->isolate();
  if (!args[0]->IsObject()) {
    return THROW_ERR_INVALID_ARG_TYPE(env, "realm must be an object");
  }
  if (!args[1]->IsObject() && !args[1]->IsNull()) {
    return THROW_ERR_INVALID_ARG_TYPE(env, "proto must be an object or null");
  }
  if (!args[4]->IsInt32() || args[4].As<Int32>()->Value() < 0 ||
      args[4].As<Int32>()->Value() >= kRemoteFlagCombinations) {
    return THROW_ERR_INVALID_ARG_TYPE(
        env, "flags must be an int32 from 0 to 3 (1 named, 2 indexed)");
  }
  int flags = args[4].As<Int32>()->Value();
  if (flags != 0 && !args[2]->IsFunction()) {
    return THROW_ERR_INVALID_ARG_TYPE(
        env, "dispatch must be a function when flags is not 0");
  }
  if (flags == 0 && !args[2]->IsFunction() && !args[2]->IsUndefined()) {
    return THROW_ERR_INVALID_ARG_TYPE(
        env, "dispatch must be a function or undefined");
  }

  Local<Context> context;
  if (!args[0].As<Object>()->GetCreationContext(isolate).ToLocal(&context)) {
    return THROW_ERR_INVALID_ARG_VALUE(env, "realm has no creation context");
  }

  Local<FunctionTemplate> tmpl =
      RemoteTemplate(isolate, GetRemoteState(env), flags);

  Local<Object> object;
  if (!tmpl->InstanceTemplate()->NewInstance(context).ToLocal(&object)) {
    return;
  }

  Local<Value> slot[] = {args[3], args[2]};
  object->SetInternalField(kRemoteSlotField,
                           Array::New(isolate, slot, arraysize(slot)));

  if (object->SetPrototypeV2(context, args[1]).IsNothing()) return;
  args.GetReturnValue().Set(object);
}

/**
 * getRemoteRef(value): the ref of a remote object, read from its internal
 * field without running any interceptor; undefined for anything else.
 */
void GetRemoteRef(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Isolate* isolate = env->isolate();
  RemoteState* state = GetRemoteState(env);
  bool is_remote = false;
  for (const Global<FunctionTemplate>& tmpl : state->templates) {
    if (!tmpl.IsEmpty() && tmpl.Get(isolate)->HasInstance(args[0])) {
      is_remote = true;
      break;
    }
  }
  if (!is_remote) return;

  Local<Array> slot = args[0]
                          .As<Object>()
                          ->GetInternalField(kRemoteSlotField)
                          .As<Value>()
                          .As<Array>();
  Local<Value> ref;
  if (!slot->Get(env->context(), 0).ToLocal(&ref)) return;
  args.GetReturnValue().Set(ref);
}

void GetRemoteNotIntercepted(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  RemoteState* state = GetRemoteState(env);
  args.GetReturnValue().Set(state->not_intercepted.Get(env->isolate()));
}

/**
 * JanusProxy(target, handler): a Proxy whose trap results are not checked
 * against `target`; prototype cycle checks walk through it via `target`.
 */
void JanusProxy(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  if (!args[0]->IsObject() || !args[1]->IsObject()) {
    return THROW_ERR_INVALID_ARG_TYPE(
        env, "target and handler must be objects");
  }

  Local<Proxy> proxy;
  if (!Proxy::NewJanus(
           env->context(), args[0].As<Object>(), args[1].As<Object>())
           .ToLocal(&proxy)) {
    return;
  }
  args.GetReturnValue().Set(proxy);
}

void IsJanusProxy(const FunctionCallbackInfo<Value>& args) {
  bool is_janus = args[0]->IsProxy() && args[0].As<Proxy>()->IsJanus();
  args.GetReturnValue().Set(is_janus);
}

/**
 * setJanusTypeof(proxy, type): typeof proxy returns `type`; only 'undefined'
 * (document.all, a callable JanusProxy) is supported.
 */
void SetJanusTypeof(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  if (!args[0]->IsProxy() || !args[0].As<Proxy>()->IsJanus()) {
    return THROW_ERR_INVALID_ARG_TYPE(env, "proxy must be a JanusProxy");
  }
  if (!args[1]->IsString()) {
    return THROW_ERR_INVALID_ARG_TYPE(env, "type must be a string");
  }
  Utf8Value type_utf8(env->isolate(), args[1]);
  std::string_view type(*type_utf8, type_utf8.length());
  if (type != "undefined") {
    return THROW_ERR_INVALID_ARG_VALUE(
        env, "only 'undefined' is supported, got '%s'", *type_utf8);
  }

  Local<Proxy> proxy = args[0].As<Proxy>();
  if (!proxy->IsFunction()) {
    return THROW_ERR_INVALID_ARG_VALUE(
        env, "typeof 'undefined' needs a callable proxy (function target)");
  }
  proxy->MarkAsUndetectable();
}

/**
 * setJanusError(proxy): Error.isError(proxy) returns true afterwards.
 */
void SetJanusError(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  if (!args[0]->IsProxy() || !args[0].As<Proxy>()->IsJanus()) {
    return THROW_ERR_INVALID_ARG_TYPE(env, "proxy must be a JanusProxy");
  }
  args[0].As<Proxy>()->MarkAsError();
}

/**
 * Makes the prototype of a context's globalThis immutable, like Window.
 */
// The globalThis of the realm whose code is calling, skipping the frames of
// the main context (the framework's own code, e.g. the Proxy trap that
// forwards the call); null when no other realm's code is on the stack.
void IncumbentGlobal(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Local<Object> global;
  if (v8::rex::IncumbentGlobalProxy(env->isolate(), env->context())
          .ToLocal(&global)) {
    args.GetReturnValue().Set(global);
  } else {
    args.GetReturnValue().SetNull();
  }
}

void LockGlobalPrototype(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  if (!args[0]->IsObject()) {
    return THROW_ERR_INVALID_ARG_TYPE(env, "global must be an object");
  }

  Local<Object> global = args[0].As<Object>();
  Local<Context> context;
  if (!global->GetCreationContext(env->isolate()).ToLocal(&context) ||
      !context->Global()->StrictEquals(global)) {
    return THROW_ERR_INVALID_ARG_VALUE(
        env, "global must be the globalThis of a context");
  }

  context->SetImmutableGlobalPrototype();
}

// RexMirror: V8 引擎自己生成的错误 (ErrorUtils::MakeGenericError) 创建后, 转给 RexMirror.native.getErrorHook()(err, template_text)。
// 没有注册 hook 时什么都不做; hook 抛异常时打印到 stderr, 不静默吞。

// 从 RexMirror.native.getErrorHook() 取 hook; 没注册或结构不对返回 false。
// 异常不在这里处理: 调用方的 TryCatch 会接住 (包括 getter 抛错)。
bool FindEngineErrorHook(v8::Isolate* isolate, Local<Context> context, Local<Value>* hook) {
  Local<Value> rex_value;
  if (!context->Global()->Get(context, FIXED_ONE_BYTE_STRING(isolate, "RexMirror")).ToLocal(&rex_value) || !rex_value->IsObject()) return false;
  Local<Value> native_value;
  if (!rex_value.As<Object>()->Get(context, FIXED_ONE_BYTE_STRING(isolate, "native")).ToLocal(&native_value) || !native_value->IsObject()) return false;
  Local<Value> getter;
  if (!native_value.As<Object>()->Get(context, FIXED_ONE_BYTE_STRING(isolate, "getErrorHook")).ToLocal(&getter) || !getter->IsFunction()) return false;
  return getter.As<Function>()->Call(context, native_value, 0, nullptr).ToLocal(hook) && (*hook)->IsFunction();
}

void EngineErrorCreated(v8::Isolate* isolate, Local<Value> error, const char* template_text) {
  v8::HandleScope scope(isolate);
  // 按 isolate 查 (每个 worker 一个 isolate); 找不到说明 env 已清理, 直接返回
  Local<Context> context;
  {
    std::lock_guard<std::mutex> lock(remote_states_mutex);
    auto found = remote_states->find(isolate);
    if (found == remote_states->end() || found->second->error_hook_context.IsEmpty()) return;
    context = found->second->error_hook_context.Get(isolate);
  }
  Context::Scope context_scope(context);
  // TryCatch 包住之后所有 JS 相关步骤: 任何异常都不能留给 MakeGenericError 的调用方
  v8::TryCatch try_catch(isolate);
  Local<Value> hook;
  if (FindEngineErrorHook(isolate, context, &hook)) {
    Local<String> text;
    if (v8::String::NewFromUtf8(isolate, template_text).ToLocal(&text)) {
      Local<Value> argv[2] = {error, text};
      Local<Value> ignored;
      // 调用失败时异常 (包括终止信号) 已被上面的 try_catch 记录, 这里不重复处理
      if (!hook.As<Function>()->Call(context, v8::Undefined(isolate), 2, argv).ToLocal(&ignored)) {
      }
    }
  }
  if (try_catch.HasCaught()) {
    // worker.terminate() / process.exit 的终止信号不能吞掉, 继续往上抛
    if (try_catch.HasTerminated()) {
      try_catch.ReThrow();
      return;
    }
    v8::String::Utf8Value message(isolate, try_catch.Exception());
    fprintf(stderr, "[RexMirror] engine error hook threw: %s\n", *message ? *message : "<unprintable>");
  }
}
// RexMirror: 由 lib/internal/bootstrap/node.js 的 setErrorHook 调用 (运行时), 注册引擎错误回调
void EnableEngineErrorHook(const v8::FunctionCallbackInfo<v8::Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Isolate* isolate = env->isolate();
  RemoteState* state = GetRemoteState(env);  // 登记 env cleanup, 随 env 释放 error_hook_context
  {
    std::lock_guard<std::mutex> lock(remote_states_mutex);
    state->error_hook_context.Reset(isolate, env->context());
  }
  isolate->SetErrorCreatedCallback(EngineErrorCreated);
}

void Initialize(Local<Object> target,
                Local<Value> unused,
                Local<Context> context,
                void* priv) {
  SetMethod(context,
            target,
            "getCreationContextGlobal",
            GetCreationContextGlobal);
  SetMethod(context, target, "getInternal", GetInternal);
  SetMethod(context, target, "createFunction", CreateFunction);
  SetMethod(context, target, "setProxySource", SetProxySource);
  SetMethod(context, target, "setIdlInterface", SetIdlInterface);
  SetMethod(context, target, "createRemoteObject", CreateRemoteObject);
  SetMethod(context, target, "getRemoteRef", GetRemoteRef);
  SetMethod(
      context, target, "getRemoteNotIntercepted", GetRemoteNotIntercepted);
  SetMethod(context, target, "JanusProxy", JanusProxy);
  SetMethod(context, target, "isJanusProxy", IsJanusProxy);
  SetMethod(context, target, "setJanusTypeof", SetJanusTypeof);
  SetMethod(context, target, "setJanusError", SetJanusError);
  SetMethod(context, target, "lockGlobalPrototype", LockGlobalPrototype);
  SetMethod(context, target, "incumbentGlobal", IncumbentGlobal);
  // RexMirror: 引擎错误回调在运行时由 enableEngineErrorHook 注册 (不在 snapshot 构建期间注册)
  SetMethod(context, target, "enableEngineErrorHook", EnableEngineErrorHook);
}

}  // namespace

void RegisterExternalReferences(ExternalReferenceRegistry* registry) {
  registry->Register(GetCreationContextGlobal);
  registry->Register(GetInternal);
  registry->Register(InvokeFunction);
  registry->Register(CreateFunction);
  registry->Register(SetProxySource);
  registry->Register(SetIdlInterface);
  registry->Register(CreateRemoteObject);
  registry->Register(GetRemoteRef);
  registry->Register(GetRemoteNotIntercepted);
  registry->Register(JanusProxy);
  registry->Register(IsJanusProxy);
  registry->Register(SetJanusTypeof);
  registry->Register(SetJanusError);
  registry->Register(LockGlobalPrototype);
  registry->Register(IncumbentGlobal);
  registry->Register(EnableEngineErrorHook);
  registry->Register(NamedGet);
  registry->Register(NamedSet);
  registry->Register(NamedQuery);
  registry->Register(NamedDelete);
  registry->Register(NamedOwnKeys);
  registry->Register(NamedDefine);
  registry->Register(NamedDescriptor);
  registry->Register(IndexedGet);
  registry->Register(IndexedSet);
  registry->Register(IndexedQuery);
  registry->Register(IndexedDelete);
  registry->Register(IndexedOwnKeys);
  registry->Register(IndexedDefine);
  registry->Register(IndexedDescriptor);
}

}  // namespace node::rex_native

NODE_BINDING_CONTEXT_AWARE_INTERNAL(rex_native, node::rex_native::Initialize)
NODE_BINDING_EXTERNAL_REFERENCE(rex_native,
                                node::rex_native::RegisterExternalReferences)
