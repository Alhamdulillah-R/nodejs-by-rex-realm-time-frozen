#include "node_realm_time.h"
#include "rexmirror_release.h"

#include "env-inl.h"
#include "ncrypto.h"
#include "node_binding.h"
#include "node_context_data.h"
#include "node_contextify.h"
#include "node_external_reference.h"
#include "node_internals.h"
#include "node_realm-inl.h"
#include "util-inl.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <iomanip>
#include <limits>
#include <memory>
#include <mutex>
#include <random>
#include <sstream>
#include <string_view>
#include <thread>
#include <unordered_map>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#endif

namespace node::realm_time {

using v8::ArrayBuffer;
using v8::Boolean;
using v8::Float64Array;
using v8::Uint8Array;
using v8::Context;
using v8::EscapableHandleScope;
using v8::Exception;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::Global;
using v8::HandleScope;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::MaybeLocal;
using v8::Message;
using v8::Null;
using v8::Number;
using v8::Object;
using v8::StackFrame;
using v8::StackTrace;
using v8::String;
using v8::Undefined;
using v8::Value;

namespace {

constexpr double kNanosecondsPerMillisecond = 1e6;
constexpr uint64_t kMaxSafeInteger = 9007199254740991ULL;
constexpr uint64_t kTokenGenerationShift = 24;
constexpr uint64_t kTokenSequenceStride = 1ULL << kTokenGenerationShift;
// Keep native completion replay aligned with the Controller terminal cache.
// A token that Go can still replay must remain commit/abort/release-idempotent
// in the Worker as well.
constexpr size_t kCompletedCallLimit = 512;
constexpr size_t kMaxControllerResponseBytes = 64 * 1024 * 1024;
constexpr size_t kDiagnosticsRecordLimit = 512;

struct CodeGenerationRecord {
  uint64_t id;
  std::string kind;
  std::string source_hash;
  std::string root_source_id;
  int context_id;
  int parent_script_id;
  int caller_line;
  int caller_column;
  uint64_t worker_id;
  uint64_t host_monotonic_ns;
  size_t source_length;
  bool replaced = false;
  bool callback_error = false;
};

struct ExceptionRecord {
  uint64_t id;
  std::string origin;
  std::string root_source_id;
  int context_id;
  int script_id;
  int line;
  int column;
  uint64_t worker_id;
  uint64_t host_monotonic_ns;
  bool replaced = false;
  bool callback_error = false;
};

struct DiagnosticsState {
  Global<Function> code_generation_callback;
  Global<Context> code_generation_context;
  Global<Context> code_generation_target_context;
  Global<Function> exception_callback;
  Global<Context> exception_context;
  Global<Context> exception_target_context;
  uint64_t code_generation_callback_generation = 0;
  uint64_t exception_callback_generation = 0;
  uint64_t next_codegen_id = 0;
  uint64_t next_exception_id = 0;
  bool in_codegen_callback = false;
  bool in_exception_callback = false;
  bool include_vm_compile = true;
  bool include_confirmed_unhandled_rejection = true;
  std::string root_source_id = "target-entry";
  std::deque<CodeGenerationRecord> code_generation_records;
  std::deque<ExceptionRecord> exception_records;
};

std::mutex diagnostics_mutex;
std::unordered_map<Environment*, std::unique_ptr<DiagnosticsState>>
    diagnostics_states;

void CleanupDiagnosticsState(void* data) {
  auto* env = static_cast<Environment*>(data);
  std::lock_guard<std::mutex> lock(diagnostics_mutex);
  diagnostics_states.erase(env);
}

DiagnosticsState* GetDiagnosticsState(Environment* env, bool create) {
  std::lock_guard<std::mutex> lock(diagnostics_mutex);
  auto found = diagnostics_states.find(env);
  if (found != diagnostics_states.end()) return found->second.get();
  if (!create) return nullptr;
  auto state = std::make_unique<DiagnosticsState>();
  DiagnosticsState* result = state.get();
  diagnostics_states.emplace(env, std::move(state));
  env->AddCleanupHook(CleanupDiagnosticsState, env);
  return result;
}

uint64_t NextSafeSequence(uint64_t* sequence) {
  *sequence = *sequence >= kMaxSafeInteger ? 1 : *sequence + 1;
  return *sequence;
}

Local<String> DiagnosticString(Isolate* isolate, std::string_view value) {
  return String::NewFromUtf8(isolate,
                             value.data(),
                             v8::NewStringType::kNormal,
                             static_cast<int>(value.size()))
      .ToLocalChecked();
}

void SetDiagnosticProperty(Local<Context> context,
                           Local<Object> target,
                           const char* name,
                           Local<Value> value) {
  target->Set(context, OneByteString(Isolate::GetCurrent(), name), value)
      .Check();
}

std::string Sha256(Local<String> source) {
  Isolate* isolate = Isolate::GetCurrent();
  Utf8Value utf8(isolate, source);
  if (*utf8 == nullptr) return {};
  ncrypto::Buffer<const unsigned char> input = {
      .data = reinterpret_cast<const unsigned char*>(*utf8),
      .len = static_cast<size_t>(utf8.length()),
  };
  ncrypto::DataPointer digest =
      ncrypto::hashDigest(input, ncrypto::Digest::SHA256);
  if (!digest) return {};
  std::ostringstream hex;
  hex << std::hex << std::setfill('0');
  const auto* bytes = digest.get<unsigned char>();
  for (size_t index = 0; index < digest.size(); index++) {
    hex << std::setw(2) << static_cast<unsigned int>(bytes[index]);
  }
  return hex.str();
}

std::string ClassifyStringCodeGeneration(Local<String> source) {
  Isolate* isolate = Isolate::GetCurrent();
  Utf8Value text(isolate, source);
  if (*text == nullptr) return "eval";
  std::string_view view(*text, static_cast<size_t>(text.length()));
  if (view.starts_with("(function anonymous(")) return "Function";
  if (view.starts_with("(async function anonymous(")) return "AsyncFunction";
  if (view.starts_with("(function* anonymous(")) return "GeneratorFunction";
  if (view.starts_with("(async function* anonymous(")) {
    return "AsyncGeneratorFunction";
  }
  return "eval";
}

std::string ExtractSourceURL(Local<String> source) {
  Isolate* isolate = Isolate::GetCurrent();
  Utf8Value text(isolate, source);
  if (*text == nullptr) return {};
  std::string_view view(*text, static_cast<size_t>(text.length()));
  constexpr std::string_view kHashMarker = "//# sourceURL=";
  constexpr std::string_view kAtMarker = "//@ sourceURL=";
  const size_t hash_position = view.rfind(kHashMarker);
  const size_t at_position = view.rfind(kAtMarker);
  size_t position;
  size_t marker_size;
  if (hash_position == std::string_view::npos &&
      at_position == std::string_view::npos) {
    return {};
  }
  if (at_position == std::string_view::npos ||
      (hash_position != std::string_view::npos &&
       hash_position > at_position)) {
    position = hash_position;
    marker_size = kHashMarker.size();
  } else {
    position = at_position;
    marker_size = kAtMarker.size();
  }
  size_t start = position + marker_size;
  while (start < view.size() &&
         std::isspace(static_cast<unsigned char>(view[start])) &&
         view[start] != '\r' && view[start] != '\n') {
    start++;
  }
  size_t end = view.find_first_of("\r\n", start);
  if (end == std::string_view::npos) end = view.size();
  while (end > start &&
         std::isspace(static_cast<unsigned char>(view[end - 1]))) {
    end--;
  }
  return std::string(view.substr(start, end - start));
}

struct CallerLocation {
  int script_id = Message::kNoScriptIdInfo;
  int line = 0;
  int column = 0;
  Local<String> script_name;
};

CallerLocation GetCallerLocation(Isolate* isolate) {
  CallerLocation result;
  Local<StackTrace> stack;
  if (!GetCurrentStackTrace(isolate, 8).ToLocal(&stack)) return result;
  for (int index = 0; index < stack->GetFrameCount(); index++) {
    Local<StackFrame> frame = stack->GetFrame(isolate, index);
    result.script_id = frame->GetScriptId();
    result.line = frame->GetLineNumber();
    result.column = frame->GetColumn();
    result.script_name = frame->GetScriptName();
    return result;
  }
  return result;
}

bool ReadActiveControl(Local<Context> context, Local<Object> data) {
  Local<Value> active;
  return data->Get(context, OneByteString(Isolate::GetCurrent(), "active"))
             .ToLocal(&active) &&
         active->IsTrue();
}

void ReplaceSourceControl(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Local<Context> context = env->context();
  Local<Object> data = args.Data().As<Object>();
  if (!ReadActiveControl(context, data)) {
    env->ThrowError("code generation control is no longer active");
    return;
  }
  if (args.Length() < 1 || !args[0]->IsString()) {
    env->ThrowTypeError("replaceSource requires a string");
    return;
  }
  SetDiagnosticProperty(context, data, "replacement", args[0]);
  args.GetReturnValue().Set(true);
}

void ReplaceExceptionControl(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Local<Context> context = env->context();
  Local<Object> data = args.Data().As<Object>();
  if (!ReadActiveControl(context, data)) {
    env->ThrowError("exception control is no longer active");
    return;
  }
  Local<Value> replacement =
      args.Length() == 0 ? Undefined(args.GetIsolate()) : args[0];
  SetDiagnosticProperty(context, data, "replacement", replacement);
  SetDiagnosticProperty(
      context, data, "hasReplacement", Boolean::New(args.GetIsolate(), true));
  args.GetReturnValue().Set(true);
}

void DisposeDiagnosticsCallback(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  DiagnosticsState* state = GetDiagnosticsState(env, false);
  if (state == nullptr || !args.Data()->IsObject()) {
    args.GetReturnValue().Set(false);
    return;
  }
  Local<Context> context = env->context();
  Local<Object> data = args.Data().As<Object>();
  Local<Value> type;
  Local<Value> generation_value;
  if (!data->Get(context, OneByteString(args.GetIsolate(), "type"))
           .ToLocal(&type) ||
      !data->Get(context, OneByteString(args.GetIsolate(), "generation"))
           .ToLocal(&generation_value) ||
      !type->IsString() || !generation_value->IsNumber()) {
    args.GetReturnValue().Set(false);
    return;
  }
  Utf8Value type_text(args.GetIsolate(), type);
  const uint64_t generation =
      static_cast<uint64_t>(generation_value.As<Number>()->Value());
  bool disposed = false;
  if (type_text.ToStringView() == "codegen" &&
      generation == state->code_generation_callback_generation) {
    state->code_generation_callback.Reset();
    state->code_generation_context.Reset();
    state->code_generation_target_context.Reset();
    state->code_generation_callback_generation++;
    disposed = true;
  } else if (type_text.ToStringView() == "exception" &&
             generation == state->exception_callback_generation) {
    state->exception_callback.Reset();
    state->exception_context.Reset();
    state->exception_target_context.Reset();
    state->exception_callback_generation++;
    disposed = true;
  }
  args.GetReturnValue().Set(disposed);
}

Local<Function> CreateDisposer(Environment* env,
                               const char* type,
                               uint64_t generation) {
  Isolate* isolate = env->isolate();
  Local<Context> context = env->context();
  Local<Object> data = Object::New(isolate);
  SetDiagnosticProperty(context, data, "type", OneByteString(isolate, type));
  SetDiagnosticProperty(
      context, data, "generation", Number::New(isolate, generation));
  return Function::New(context, DisposeDiagnosticsCallback, data)
      .ToLocalChecked();
}

bool ReadBooleanOption(Environment* env,
                       Local<Object> options,
                       const char* name,
                       bool default_value) {
  Local<Value> value;
  if (!options->Get(env->context(), OneByteString(env->isolate(), name))
           .ToLocal(&value) ||
      value->IsUndefined()) {
    return default_value;
  }
  return value->BooleanValue(env->isolate());
}

std::string ReadStringOption(Environment* env,
                             Local<Object> options,
                             const char* name,
                             std::string default_value) {
  Local<Value> value;
  if (!options->Get(env->context(), OneByteString(env->isolate(), name))
           .ToLocal(&value) ||
      value->IsUndefined() || !value->IsString()) {
    return default_value;
  }
  Utf8Value text(env->isolate(), value);
  return *text == nullptr
             ? std::move(default_value)
             : std::string(*text, static_cast<size_t>(text.length()));
}

bool ReadTargetContextOption(Environment* env,
                             Local<Object> options,
                             Local<Context>* result) {
  Local<Value> value;
  if (!options->Get(env->context(), OneByteString(env->isolate(), "context"))
           .ToLocal(&value) ||
      value->IsNullOrUndefined()) {
    *result = Local<Context>();
    return true;
  }
  if (!value->IsObject()) {
    env->ThrowTypeError("diagnostics context must be a contextified vm object");
    return false;
  }
  contextify::ContextifyContext* context =
      contextify::ContextifyContext::ContextFromContextifiedSandbox(
          env, value.As<Object>());
  if (context == nullptr) {
    env->ThrowTypeError("diagnostics context must be a contextified vm object");
    return false;
  }
  *result = context->context();
  return true;
}

void SetCodeGenerationCallbackBinding(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  if (args.Length() < 1 || !args[0]->IsFunction()) {
    env->ThrowTypeError("setCodeGenerationCallback requires a function");
    return;
  }
  Local<Object> options = Object::New(args.GetIsolate());
  if (args.Length() >= 2 && !args[1]->IsUndefined()) {
    if (!args[1]->IsObject()) {
      env->ThrowTypeError("code generation callback options must be an object");
      return;
    }
    options = args[1].As<Object>();
  }
  DiagnosticsState* state = GetDiagnosticsState(env, true);
  Local<Context> target_context;
  if (!ReadTargetContextOption(env, options, &target_context)) return;
  state->code_generation_callback.Reset(args.GetIsolate(),
                                        args[0].As<Function>());
  state->code_generation_context.Reset(args.GetIsolate(), env->context());
  if (target_context.IsEmpty()) {
    state->code_generation_target_context.Reset();
  } else {
    state->code_generation_target_context.Reset(args.GetIsolate(),
                                                target_context);
  }
  state->root_source_id =
      ReadStringOption(env, options, "rootSource", "target-entry");
  state->include_vm_compile =
      ReadBooleanOption(env, options, "includeVmCompile", true);
  state->code_generation_callback_generation++;
  args.GetReturnValue().Set(CreateDisposer(
      env, "codegen", state->code_generation_callback_generation));
}

void SetUncaughtExceptionCallbackBinding(
    const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  if (args.Length() < 1 || !args[0]->IsFunction()) {
    env->ThrowTypeError("setUncaughtExceptionCallback requires a function");
    return;
  }
  Local<Object> options = Object::New(args.GetIsolate());
  if (args.Length() >= 2 && !args[1]->IsUndefined()) {
    if (!args[1]->IsObject()) {
      env->ThrowTypeError("exception callback options must be an object");
      return;
    }
    options = args[1].As<Object>();
  }
  DiagnosticsState* state = GetDiagnosticsState(env, true);
  Local<Context> target_context;
  if (!ReadTargetContextOption(env, options, &target_context)) return;
  state->exception_callback.Reset(args.GetIsolate(), args[0].As<Function>());
  state->exception_context.Reset(args.GetIsolate(), env->context());
  if (target_context.IsEmpty()) {
    state->exception_target_context.Reset();
  } else {
    state->exception_target_context.Reset(args.GetIsolate(), target_context);
  }
  state->include_confirmed_unhandled_rejection = ReadBooleanOption(
      env, options, "includeConfirmedUnhandledRejection", true);
  state->root_source_id =
      ReadStringOption(env, options, "rootSource", state->root_source_id);
  state->exception_callback_generation++;
  args.GetReturnValue().Set(
      CreateDisposer(env, "exception", state->exception_callback_generation));
}

void GetCodeGenerationRecordsBinding(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  DiagnosticsState* state = GetDiagnosticsState(env, false);
  Isolate* isolate = args.GetIsolate();
  Local<Context> context = env->context();
  const size_t count =
      state == nullptr ? 0 : state->code_generation_records.size();
  Local<v8::Array> records = v8::Array::New(isolate, static_cast<int>(count));
  if (state != nullptr) {
    uint32_t index = 0;
    for (const CodeGenerationRecord& record : state->code_generation_records) {
      Local<Object> item = Object::New(isolate);
      SetDiagnosticProperty(
          context, item, "codegenId", Number::New(isolate, record.id));
      SetDiagnosticProperty(
          context, item, "kind", DiagnosticString(isolate, record.kind));
      SetDiagnosticProperty(context,
                            item,
                            "sourceHash",
                            DiagnosticString(isolate, record.source_hash));
      SetDiagnosticProperty(context,
                            item,
                            "rootSourceId",
                            DiagnosticString(isolate, record.root_source_id));
      SetDiagnosticProperty(context,
                            item,
                            "parentScriptId",
                            Integer::New(isolate, record.parent_script_id));
      SetDiagnosticProperty(
          context, item, "replaced", Boolean::New(isolate, record.replaced));
      SetDiagnosticProperty(context,
                            item,
                            "callbackError",
                            Boolean::New(isolate, record.callback_error));
      records->Set(context, index++, item).Check();
    }
  }
  args.GetReturnValue().Set(records);
}

void GetExceptionRecordsBinding(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  DiagnosticsState* state = GetDiagnosticsState(env, false);
  Isolate* isolate = args.GetIsolate();
  Local<Context> context = env->context();
  const size_t count = state == nullptr ? 0 : state->exception_records.size();
  Local<v8::Array> records = v8::Array::New(isolate, static_cast<int>(count));
  if (state != nullptr) {
    uint32_t index = 0;
    for (const ExceptionRecord& record : state->exception_records) {
      Local<Object> item = Object::New(isolate);
      SetDiagnosticProperty(
          context, item, "exceptionId", Number::New(isolate, record.id));
      SetDiagnosticProperty(
          context, item, "origin", DiagnosticString(isolate, record.origin));
      SetDiagnosticProperty(context,
                            item,
                            "rootSourceId",
                            DiagnosticString(isolate, record.root_source_id));
      SetDiagnosticProperty(
          context, item, "scriptId", Integer::New(isolate, record.script_id));
      SetDiagnosticProperty(
          context, item, "line", Integer::New(isolate, record.line));
      SetDiagnosticProperty(
          context, item, "column", Integer::New(isolate, record.column));
      SetDiagnosticProperty(
          context, item, "replaced", Boolean::New(isolate, record.replaced));
      SetDiagnosticProperty(context,
                            item,
                            "callbackError",
                            Boolean::New(isolate, record.callback_error));
      records->Set(context, index++, item).Check();
    }
  }
  args.GetReturnValue().Set(records);
}

struct ProcessClockSnapshot {
  bool enabled;
  bool frozen;
  double wall_time_offset_ms;
  double monotonic_time_offset_ns;
  double frozen_wall_time_ms;
  double frozen_monotonic_time_ns;
};

// A Realm is a process boundary.  Contexts and Worker isolates still own a
// controller object for binding resolution, but every target-visible clock
// reads this one process projection.  The sequence counter makes the hot clock
// read path lock-free while the single active owner serializes writes.
struct ProcessClockState {
  std::atomic<uint64_t> sequence{0};
  std::atomic<const RealmTimeController*> owner{nullptr};
  std::atomic<bool> enabled{false};
  std::atomic<bool> frozen{false};
  std::atomic<double> wall_time_offset_ms{0};
  std::atomic<double> monotonic_time_offset_ns{0};
  std::atomic<double> frozen_wall_time_ms{0};
  std::atomic<double> frozen_monotonic_time_ns{0};
};

ProcessClockState process_clock;

void BeginProcessClockWrite() {
  process_clock.sequence.fetch_add(1, std::memory_order_acq_rel);
}

void EndProcessClockWrite() {
  process_clock.sequence.fetch_add(1, std::memory_order_release);
}

bool EnableProcessClock(const RealmTimeController* owner) {
  const RealmTimeController* expected = nullptr;
  if (!process_clock.owner.compare_exchange_strong(
          expected, owner, std::memory_order_acq_rel)) {
    return expected == owner;
  }
  BeginProcessClockWrite();
  process_clock.wall_time_offset_ms.store(0, std::memory_order_relaxed);
  process_clock.monotonic_time_offset_ns.store(0, std::memory_order_relaxed);
  process_clock.frozen_wall_time_ms.store(0, std::memory_order_relaxed);
  process_clock.frozen_monotonic_time_ns.store(0, std::memory_order_relaxed);
  process_clock.frozen.store(false, std::memory_order_relaxed);
  process_clock.enabled.store(true, std::memory_order_relaxed);
  EndProcessClockWrite();
  return true;
}

void DisableProcessClock(const RealmTimeController* owner) {
  if (process_clock.owner.load(std::memory_order_acquire) != owner) return;
  BeginProcessClockWrite();
  process_clock.enabled.store(false, std::memory_order_relaxed);
  process_clock.frozen.store(false, std::memory_order_relaxed);
  process_clock.wall_time_offset_ms.store(0, std::memory_order_relaxed);
  process_clock.monotonic_time_offset_ns.store(0, std::memory_order_relaxed);
  process_clock.frozen_wall_time_ms.store(0, std::memory_order_relaxed);
  process_clock.frozen_monotonic_time_ns.store(0, std::memory_order_relaxed);
  EndProcessClockWrite();
  process_clock.owner.store(nullptr, std::memory_order_release);
}

bool FreezeProcessClock(const RealmTimeController* owner,
                        double wall_time_ms,
                        double monotonic_time_ns) {
  if (process_clock.owner.load(std::memory_order_acquire) != owner ||
      !process_clock.enabled.load(std::memory_order_acquire)) {
    return false;
  }
  BeginProcessClockWrite();
  process_clock.frozen_wall_time_ms.store(wall_time_ms,
                                          std::memory_order_relaxed);
  process_clock.frozen_monotonic_time_ns.store(monotonic_time_ns,
                                               std::memory_order_relaxed);
  process_clock.frozen.store(true, std::memory_order_relaxed);
  EndProcessClockWrite();
  return true;
}

bool ResumeProcessClock(const RealmTimeController* owner,
                        double wall_time_offset_ms,
                        double monotonic_time_offset_ns) {
  if (process_clock.owner.load(std::memory_order_acquire) != owner ||
      !std::isfinite(wall_time_offset_ms) ||
      !std::isfinite(monotonic_time_offset_ns)) {
    return false;
  }
  BeginProcessClockWrite();
  process_clock.wall_time_offset_ms.store(wall_time_offset_ms,
                                          std::memory_order_relaxed);
  process_clock.monotonic_time_offset_ns.store(monotonic_time_offset_ns,
                                               std::memory_order_relaxed);
  process_clock.frozen.store(false, std::memory_order_relaxed);
  EndProcessClockWrite();
  return true;
}

ProcessClockSnapshot ReadProcessClock() {
  ProcessClockSnapshot snapshot;
  uint64_t before;
  uint64_t after;
  do {
    before = process_clock.sequence.load(std::memory_order_acquire);
    if (before & 1) continue;
    snapshot.enabled = process_clock.enabled.load(std::memory_order_relaxed);
    snapshot.frozen = process_clock.frozen.load(std::memory_order_relaxed);
    snapshot.wall_time_offset_ms =
        process_clock.wall_time_offset_ms.load(std::memory_order_relaxed);
    snapshot.monotonic_time_offset_ns =
        process_clock.monotonic_time_offset_ns.load(std::memory_order_relaxed);
    snapshot.frozen_wall_time_ms =
        process_clock.frozen_wall_time_ms.load(std::memory_order_relaxed);
    snapshot.frozen_monotonic_time_ns =
        process_clock.frozen_monotonic_time_ns.load(std::memory_order_relaxed);
    after = process_clock.sequence.load(std::memory_order_acquire);
  } while (before != after || (after & 1));
  return snapshot;
}

// Blink TimeClamper port (third_party/blink/renderer/core/timing/
// time_clamper.cc).  The quantum comes from REX_CLOCK_RESOLUTION_NS, the
// per-process secret makes bucket thresholds unpredictable across runs.
struct ClockSurfaceConfig {
  int64_t resolution_ns;
  uint64_t secret;
  bool nesting_clamp;
  bool high_resolution_timer;
};

uint64_t RandomClockSecret() {
  std::random_device device;
  return (static_cast<uint64_t>(device()) << 32) ^
         static_cast<uint64_t>(device());
}

// Process-wide, mutable after startup (RexMirror.clock.set).  The secret is
// fixed for the life of the process like a renderer's TimeClamper.
struct ClockSurfaceState {
  std::atomic<int64_t> resolution_ns{0};
  std::atomic<bool> nesting_clamp{false};
  std::atomic<bool> high_resolution_timer{false};
  uint64_t secret = 0;
};

// ---- clock trace ring ------------------------------------------------------
struct ClockTraceRecord {
  uint64_t seq;
  uint64_t real_ns;
  double value;
  double aux0;
  double aux1;
  uint8_t kind;
};

struct ClockTraceState {
  std::atomic<bool> enabled{false};
  std::mutex mutex;
  std::vector<ClockTraceRecord> ring;
  size_t head = 0;   // next slot to write
  size_t count = 0;  // live records
  uint64_t next_seq = 0;
  uint64_t dropped = 0;  // overwritten since the last drain
  uint64_t total = 0;    // recorded since start
  uint64_t start_ns = 0;
};

ClockTraceState& ClockTrace() {
  static ClockTraceState state;
  return state;
}

struct ClockRulesState {
  std::atomic<double> performance_now_offset_ms{0};
  std::atomic<double> date_offset_ms{0};
};

ClockRulesState& ClockRules() {
  static ClockRulesState state;
  return state;
}

constexpr size_t kClockTraceDefaultCapacity = 65536;
constexpr size_t kClockTraceMaxCapacity = size_t{1} << 24;

#ifdef _WIN32
// Chrome raises the system timer through ntdll rather than winmm's
// timeBeginPeriod; do the same so the effect (and its footprint) match.
using NtSetTimerResolutionFn = LONG(NTAPI*)(ULONG, BOOLEAN, PULONG);
using NtQueryTimerResolutionFn = LONG(NTAPI*)(PULONG, PULONG, PULONG);
constexpr ULONG kOneMillisecondIn100ns = 10000;
constexpr LONG kStatusTimerResolutionNotSet = static_cast<LONG>(0xC0000245);

NtSetTimerResolutionFn NtSetTimerResolutionPtr() {
  static const NtSetTimerResolutionFn fn = [] {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    return ntdll == nullptr ? nullptr
                            : reinterpret_cast<NtSetTimerResolutionFn>(
                                  GetProcAddress(ntdll, "NtSetTimerResolution"));
  }();
  return fn;
}

NtQueryTimerResolutionFn NtQueryTimerResolutionPtr() {
  static const NtQueryTimerResolutionFn fn = [] {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    return ntdll == nullptr ? nullptr
                            : reinterpret_cast<NtQueryTimerResolutionFn>(
                                  GetProcAddress(ntdll, "NtQueryTimerResolution"));
  }();
  return fn;
}

bool ApplyHighResolutionTimer(bool enable, std::string* error) {
  NtSetTimerResolutionFn set_resolution = NtSetTimerResolutionPtr();
  if (set_resolution == nullptr) {
    *error = "highResolutionTimer: NtSetTimerResolution is unavailable";
    return false;
  }
  ULONG actual = 0;
  const LONG status =
      set_resolution(kOneMillisecondIn100ns, enable ? TRUE : FALSE, &actual);
  // Releasing a request this process never made is not an error.
  if (status < 0 && !(status == kStatusTimerResolutionNotSet && !enable)) {
    *error = "highResolutionTimer: NtSetTimerResolution failed";
    return false;
  }
  return true;
}

double PlatformTimerResolutionMs() {
  NtQueryTimerResolutionFn query = NtQueryTimerResolutionPtr();
  if (query == nullptr) return 0;
  ULONG minimum = 0;
  ULONG maximum = 0;
  ULONG current = 0;
  if (query(&minimum, &maximum, &current) < 0) return 0;
  return static_cast<double>(current) / kOneMillisecondIn100ns;
}
#else
bool ApplyHighResolutionTimer(bool, std::string*) {
  return true;
}

double PlatformTimerResolutionMs() {
  struct timespec resolution;
  if (clock_getres(CLOCK_MONOTONIC, &resolution) != 0) return 0;
  return static_cast<double>(resolution.tv_sec) * 1e3 +
         static_cast<double>(resolution.tv_nsec) / 1e6;
}
#endif

ClockSurfaceConfig ParseClockSurfaceEnvironment(uint64_t secret);

ClockSurfaceState& ClockSurface() {
  static ClockSurfaceState state;
  static std::once_flag once;
  std::call_once(once, [] {
    const ClockSurfaceConfig initial =
        ParseClockSurfaceEnvironment(RandomClockSecret());
    state.secret = initial.secret;
    state.resolution_ns.store(initial.resolution_ns,
                              std::memory_order_relaxed);
    state.nesting_clamp.store(initial.nesting_clamp,
                              std::memory_order_relaxed);
    state.high_resolution_timer.store(initial.high_resolution_timer,
                                      std::memory_order_relaxed);
    if (initial.high_resolution_timer) {
      std::string error;
      if (!ApplyHighResolutionTimer(true, &error)) {
        fprintf(stderr, "REX_TIMER_HIGHRES: %s\n", error.c_str());
        exit(9);
      }
    }
  });
  return state;
}

// Snapshot for the hot paths; the atomics make it consistent enough per read.
ClockSurfaceConfig GetClockSurfaceConfig() {
  ClockSurfaceState& state = ClockSurface();
  return ClockSurfaceConfig{
      state.resolution_ns.load(std::memory_order_relaxed),
      state.secret,
      state.nesting_clamp.load(std::memory_order_relaxed),
      state.high_resolution_timer.load(std::memory_order_relaxed)};
}

ClockSurfaceConfig ParseClockSurfaceEnvironment(uint64_t secret) {
  {
    ClockSurfaceConfig result{0, secret, false, false};
    std::string raw;
    if (credentials::SafeGetenv("REX_CLOCK_RESOLUTION_NS", &raw) &&
        !raw.empty()) {
      char* end = nullptr;
      const double nanoseconds = std::strtod(raw.c_str(), &end);
      if (end == raw.c_str() || *end != '\0' ||
          !std::isfinite(nanoseconds) || nanoseconds < 0 ||
          nanoseconds != std::floor(nanoseconds) || nanoseconds > 1e12) {
        fprintf(stderr,
                "REX_CLOCK_RESOLUTION_NS: invalid value '%s' "
                "(whole nanoseconds, 0..1e12)\n",
                raw.c_str());
        exit(9);
      }
      result.resolution_ns = static_cast<int64_t>(nanoseconds);
    }
    raw.clear();
    if (credentials::SafeGetenv("REX_TIMER_NESTING_CLAMP", &raw) &&
        !raw.empty() && raw != "0") {
      if (raw != "1") {
        fprintf(stderr,
                "REX_TIMER_NESTING_CLAMP: must be 0 or 1, got '%s'\n",
                raw.c_str());
        exit(9);
      }
      result.nesting_clamp = true;
    }
    raw.clear();
    if (credentials::SafeGetenv("REX_TIMER_HIGHRES", &raw) && !raw.empty() &&
        raw != "0") {
      if (raw != "1") {
        fprintf(stderr,
                "REX_TIMER_HIGHRES: must be 0 or 1, got '%s'\n",
                raw.c_str());
        exit(9);
      }
      result.high_resolution_timer = true;
    }
    return result;
  }
}

uint64_t MurmurHash3Finalize(uint64_t value) {
  value ^= value >> 33;
  value *= UINT64_C(0xff51afd7ed558ccd);
  value ^= value >> 33;
  value *= UINT64_C(0xc4ceb9fe1a85ec53);
  value ^= value >> 33;
  return value;
}

// Uniform [0, 1) from the hash mantissa, same construction as Blink.
double UnitIntervalFromHash(uint64_t hash) {
  constexpr uint64_t kExponentBits = UINT64_C(0x3FF0000000000000);
  constexpr uint64_t kMantissaMask = UINT64_C(0x000FFFFFFFFFFFFF);
  const uint64_t bits = (hash & kMantissaMask) | kExponentBits;
  double result;
  std::memcpy(&result, &bits, sizeof(result));
  return result - 1.0;
}

// Blink splits the value into its lower ten decimal digits and the rest so
// the threshold hash sees small numbers; keep that so the dithering is
// bit-for-bit the renderer's given the same secret.
constexpr int64_t kTenLowerDigitsMod = INT64_C(10000000000);

int64_t ClampToRendererQuantum(int64_t microseconds) {
  const ClockSurfaceConfig& config = GetClockSurfaceConfig();
  // The quantum is configured in nanoseconds; Blink works in microseconds.
  const int64_t resolution = config.resolution_ns / 1000;
  if (resolution <= 0) return microseconds;

  bool negative = false;
  if (microseconds < 0) {
    negative = true;
    microseconds =
        -std::max(-std::numeric_limits<int64_t>::max(), microseconds);
  }
  const int64_t lower_digits = microseconds % kTenLowerDigitsMod;
  int64_t upper_digits = microseconds - lower_digits;

  int64_t clamped = lower_digits - lower_digits % resolution;
  const uint64_t hash =
      MurmurHash3Finalize(static_cast<uint64_t>(clamped) ^ config.secret);
  const double threshold =
      static_cast<double>(clamped) +
      static_cast<double>(resolution) * UnitIntervalFromHash(hash);
  if (static_cast<double>(lower_digits) >= threshold) clamped += resolution;

  upper_digits =
      std::min(upper_digits, std::numeric_limits<int64_t>::max() - clamped);
  clamped += upper_digits;
  return negative ? -clamped : clamped;
}

// TimeDelta::InMillisecondsF(): microseconds / 1000.0 as a double.
double MicrosecondsToMillisecondsF(int64_t microseconds) {
  return static_cast<double>(microseconds) / 1000.0;
}

#ifdef _WIN32
using NativeSocket = SOCKET;
constexpr NativeSocket kInvalidSocket = INVALID_SOCKET;
#else
using NativeSocket = int;
constexpr NativeSocket kInvalidSocket = -1;
#endif

void CloseNativeSocket(NativeSocket socket) {
#ifdef _WIN32
  closesocket(socket);
#else
  close(socket);
#endif
}

bool SendAll(NativeSocket socket, std::string_view data) {
  while (!data.empty()) {
#ifdef MSG_NOSIGNAL
    constexpr int flags = MSG_NOSIGNAL;
#else
    constexpr int flags = 0;
#endif
    int sent = send(socket,
                    data.data(),
                    static_cast<int>(std::min<size_t>(
                        data.size(), std::numeric_limits<int>::max())),
                    flags);
    if (sent <= 0) return false;
    data.remove_prefix(static_cast<size_t>(sent));
  }
  return true;
}

std::string ToLower(std::string_view input) {
  std::string result(input);
  for (char& character : result) {
    character =
        static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
  }
  return result;
}

bool DecodeChunkedBody(std::string_view encoded, std::string* decoded) {
  while (true) {
    size_t line_end = encoded.find("\r\n");
    if (line_end == std::string_view::npos) return false;
    std::string size_text(encoded.substr(0, line_end));
    size_t extension = size_text.find(';');
    if (extension != std::string::npos) size_text.resize(extension);
    if (size_text.empty()) return false;
    char* end = nullptr;
    errno = 0;
    unsigned long long chunk_size = std::strtoull(size_text.c_str(), &end, 16);
    if (errno != 0 || end == size_text.c_str() || *end != '\0') return false;
    encoded.remove_prefix(line_end + 2);
    if (chunk_size == 0) return true;
    if (chunk_size > kMaxControllerResponseBytes ||
        chunk_size > encoded.size() ||
        encoded.size() - static_cast<size_t>(chunk_size) < 2 ||
        encoded.substr(static_cast<size_t>(chunk_size), 2) != "\r\n" ||
        decoded->size() > kMaxControllerResponseBytes - chunk_size) {
      return false;
    }
    decoded->append(encoded.data(), static_cast<size_t>(chunk_size));
    encoded.remove_prefix(static_cast<size_t>(chunk_size) + 2);
  }
}

bool ParseHttpResponse(std::string_view response,
                       int* status_code,
                       std::string* body) {
  size_t header_end = response.find("\r\n\r\n");
  if (header_end == std::string_view::npos) return false;
  std::string_view headers = response.substr(0, header_end);
  std::string_view encoded_body = response.substr(header_end + 4);
  size_t status_end = headers.find("\r\n");
  std::string_view status_line = headers.substr(0, status_end);
  size_t first_space = status_line.find(' ');
  if (first_space == std::string_view::npos ||
      status_line.size() < first_space + 4) {
    return false;
  }
  *status_code =
      std::atoi(std::string(status_line.substr(first_space + 1, 3)).c_str());
  if (*status_code < 100 || *status_code > 999) return false;

  bool chunked = false;
  size_t content_length = std::string::npos;
  size_t cursor =
      status_end == std::string_view::npos ? headers.size() : status_end + 2;
  while (cursor < headers.size()) {
    size_t line_end = headers.find("\r\n", cursor);
    if (line_end == std::string_view::npos) line_end = headers.size();
    std::string_view line = headers.substr(cursor, line_end - cursor);
    size_t colon = line.find(':');
    if (colon != std::string_view::npos) {
      std::string name = ToLower(line.substr(0, colon));
      std::string_view value = line.substr(colon + 1);
      while (!value.empty() &&
             std::isspace(static_cast<unsigned char>(value.front()))) {
        value.remove_prefix(1);
      }
      if (name == "transfer-encoding" &&
          ToLower(value).find("chunked") != std::string::npos) {
        chunked = true;
      } else if (name == "content-length") {
        while (!value.empty() && std::isspace(
                                     static_cast<unsigned char>(value.back()))) {
          value.remove_suffix(1);
        }
        std::string value_text(value);
        char* end = nullptr;
        unsigned long long parsed =
            std::strtoull(value_text.c_str(), &end, 10);
        if (end == nullptr || *end != '\0' ||
            parsed > kMaxControllerResponseBytes) {
          return false;
        }
        content_length = static_cast<size_t>(parsed);
      }
    }
    cursor = line_end + 2;
  }

  if (chunked) return DecodeChunkedBody(encoded_body, body);
  if (content_length != std::string::npos) {
    if (encoded_body.size() < content_length) return false;
    body->assign(encoded_body.data(), content_length);
  } else {
    if (encoded_body.size() > kMaxControllerResponseBytes) return false;
    body->assign(encoded_body);
  }
  return true;
}

uint64_t TokenGeneration(uint64_t token) {
  return token >> kTokenGenerationShift;
}

struct ControllerHttpResponse {
  int status_code;
  std::string body;
};

bool PerformControllerPost(Environment* env,
                           uint32_t port,
                           std::string_view path,
                            std::string_view body,
                            uint64_t token,
                            uint64_t generation,
                            ControllerHttpResponse* result) {
  NativeSocket socket_handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (socket_handle == kInvalidSocket) {
    env->ThrowError("failed to create Controller socket");
    return false;
  }

  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(static_cast<uint16_t>(port));
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (connect(socket_handle,
              reinterpret_cast<const sockaddr*>(&address),
              sizeof(address)) != 0) {
    CloseNativeSocket(socket_handle);
    env->ThrowError("failed to connect to the loopback Controller");
    return false;
  }

  std::string request;
  request.reserve(body.size() + path.size() + 320);
  request.append("POST ").append(path).append(" HTTP/1.1\r\n");
  request.append("Host: 127.0.0.1:")
      .append(std::to_string(port))
      .append("\r\n");
  request.append("Content-Type: application/json\r\n");
  request.append("Connection: close\r\n");
  request.append("X-Rex-Realm-Park-Ack: 1\r\n");
  request.append("X-Rex-Realm-Token: ")
      .append(std::to_string(token))
      .append("\r\n");
  request.append("X-Rex-Realm-Generation: ")
      .append(std::to_string(generation))
      .append("\r\n");
  request.append("X-Rex-Realm-Worker-Pid: ")
      .append(std::to_string(uv_os_getpid()))
      .append("\r\n");
#ifdef _WIN32
  request.append("X-Rex-Realm-Control-Tid: ")
      .append(std::to_string(GetCurrentThreadId()))
      .append("\r\n");
#endif
  request.append("Content-Length: ")
      .append(std::to_string(body.size()))
      .append("\r\n\r\n")
      .append(body);

  if (!SendAll(socket_handle, request)) {
    CloseNativeSocket(socket_handle);
    env->ThrowError("failed to send the parked Controller request");
    return false;
  }

  std::string response;
  char buffer[16 * 1024];
  while (true) {
    int received = recv(socket_handle, buffer, sizeof(buffer), 0);
    if (received == 0) break;
    if (received < 0) {
      CloseNativeSocket(socket_handle);
      env->ThrowError("failed to receive the Controller response");
      return false;
    }
    if (response.size() > kMaxControllerResponseBytes + 64 * 1024 - received) {
      CloseNativeSocket(socket_handle);
      env->ThrowRangeError("Controller response exceeds the 64 MiB limit");
      return false;
    }
    response.append(buffer, static_cast<size_t>(received));

    // Once the framed body is present, ParseHttpResponse has everything it
    // needs; closing locally avoids depending on HTTP connection teardown.
    const size_t header_end = response.find("\r\n\r\n");
    if (header_end != std::string::npos) {
      const std::string_view headers(response.data(), header_end);
      size_t content_length = std::string::npos;
      size_t line_start = 0;
      while (line_start < headers.size()) {
        const size_t line_end = headers.find("\r\n", line_start);
        const size_t end = line_end == std::string::npos ? headers.size()
                                                           : line_end;
        const std::string_view line = headers.substr(line_start, end - line_start);
        const size_t colon = line.find(':');
        if (colon != std::string::npos) {
          std::string name(line.substr(0, colon));
          std::transform(name.begin(), name.end(), name.begin(),
                         [](unsigned char c) {
                           return static_cast<char>(std::tolower(c));
                         });
          if (name == "content-length") {
            std::string value(line.substr(colon + 1));
            size_t first = 0;
            while (first < value.size() &&
                   std::isspace(static_cast<unsigned char>(value[first]))) {
              ++first;
            }
            size_t last = value.size();
            while (last > first &&
                   std::isspace(static_cast<unsigned char>(value[last - 1]))) {
              --last;
            }
            value = value.substr(first, last - first);
            char* end_ptr = nullptr;
            errno = 0;
            const unsigned long long parsed =
                std::strtoull(value.c_str(), &end_ptr, 10);
            if (errno == 0 && end_ptr != value.c_str() && *end_ptr == '\0' &&
                parsed <= kMaxControllerResponseBytes) {
              content_length = static_cast<size_t>(parsed);
            }
            break;
          }
        }
        if (line_end == std::string::npos) break;
        line_start = line_end + 2;
      }
      if (content_length != std::string::npos &&
          response.size() >= header_end + 4 + content_length) {
        break;
      }
    }
  }
  CloseNativeSocket(socket_handle);

  if (!ParseHttpResponse(response,
                         &result->status_code,
                         &result->body)) {
    env->ThrowError("Controller returned an invalid HTTP response");
    return false;
  }
  return true;
}

double RealWallTimeMilliseconds(Environment* env) {
  return std::floor(env->isolate_data()->platform()->CurrentClockTimeMillis());
}

uint64_t RealMonotonicTimeNanoseconds() {
  return uv_hrtime();
}

int64_t RealmDateNowCallback(Isolate* isolate, int64_t real_time_millis) {
  HandleScope handle_scope(isolate);
  double result =
      CurrentWallTimeMilliseconds(real_time_millis) + DateOffsetMilliseconds();
  if (!std::isfinite(result) ||
      result < static_cast<double>(std::numeric_limits<int64_t>::min()) ||
      result > static_cast<double>(std::numeric_limits<int64_t>::max())) {
    return real_time_millis;
  }
  const int64_t floored = static_cast<int64_t>(std::floor(result));
  if (ClockTraceEnabled()) {
    TraceClockRead(ClockTraceKind::kDate,
                   uv_hrtime(),
                   static_cast<double>(floored),
                   0,
                   static_cast<double>(ObservedContextOf(isolate)));
  }
  return floored;
}

RealmTimeController* ResolveController(
    const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  if (args.Length() == 0 || args[0]->IsNullOrUndefined()) {
    RealmTimeController* controller = GetCurrentController(env->isolate());
    if (controller == nullptr) {
      env->ThrowError("realm time is unavailable in the current context");
    }
    return controller;
  }

  if (!args[0]->IsObject()) {
    env->ThrowTypeError(
        "context must be a contextified vm object, null, or undefined");
    return nullptr;
  }

  contextify::ContextifyContext* context =
      contextify::ContextifyContext::ContextFromContextifiedSandbox(
          env, args[0].As<Object>());
  if (context == nullptr) {
    env->ThrowTypeError("context must be a contextified vm object");
    return nullptr;
  }
  return context->realm_time_controller();
}

bool ReadToken(Environment* env, Local<Value> value, uint64_t* result) {
  if (!value->IsNumber()) {
    env->ThrowTypeError("token must be a number");
    return false;
  }
  double token = value.As<Number>()->Value();
  if (!std::isfinite(token) || token < 1 || token > kMaxSafeInteger ||
      std::floor(token) != token) {
    env->ThrowRangeError("token must be a positive safe integer");
    return false;
  }
  *result = static_cast<uint64_t>(token);
  return true;
}

bool ReadControllerPort(Environment* env,
                        Local<Value> value,
                        uint32_t* result) {
  if (!value->IsUint32()) {
    env->ThrowTypeError("port must be an unsigned integer");
    return false;
  }
  uint32_t port = value.As<Integer>()->Value();
  if (port == 0 || port > 65535) {
    env->ThrowRangeError("port must be between 1 and 65535");
    return false;
  }
  *result = port;
  return true;
}

bool ReadControllerPath(Environment* env,
                        Local<Value> value,
                        std::string* result) {
  if (!value->IsString()) {
    env->ThrowTypeError("path must be a string");
    return false;
  }
  Utf8Value path_value(env->isolate(), value);
  if (*path_value == nullptr || path_value.length() == 0 ||
      (*path_value)[0] != '/' ||
      std::string_view(*path_value, path_value.length())
              .find_first_of("\r\n") != std::string_view::npos) {
    env->ThrowRangeError("path must be an absolute HTTP path without newlines");
    return false;
  }
  result->assign(*path_value, path_value.length());
  return true;
}

bool ReadDuration(Environment* env, Local<Value> value, double* result) {
  if (!value->IsNumber()) {
    env->ThrowTypeError("duration must be a number");
    return false;
  }
  double duration = value.As<Number>()->Value();
  if (!std::isfinite(duration) || duration < 0) {
    env->ThrowRangeError("functionDurationMs must be finite and non-negative");
    return false;
  }
  *result = duration;
  return true;
}

bool ReadAdjustment(Environment* env, Local<Value> value, double* result) {
  if (!value->IsNumber()) {
    env->ThrowTypeError("timelineAdjustmentMs must be a number");
    return false;
  }
  double adjustment = value.As<Number>()->Value();
  if (!std::isfinite(adjustment)) {
    env->ThrowRangeError("timelineAdjustmentMs must be finite");
    return false;
  }
  *result = adjustment;
  return true;
}

bool ReadOperation(Environment* env,
                   const FunctionCallbackInfo<Value>& args,
                   std::string* result) {
  if (args.Length() < 2 || args[1]->IsUndefined()) {
    *result = "external";
    return true;
  }
  if (!args[1]->IsString()) {
    env->ThrowTypeError("operation must be a string");
    return false;
  }
  Utf8Value operation(env->isolate(), args[1]);
  if (*operation == nullptr || operation.length() == 0) {
    env->ThrowRangeError("operation must not be empty");
    return false;
  }
  result->assign(*operation, operation.length());
  return true;
}

bool ReturnTransactionResult(Environment* env,
                             RealmTimeController::TransactionResult result) {
  using Result = RealmTimeController::TransactionResult;
  switch (result) {
    case Result::kOk:
    case Result::kIdempotent:
      return true;
    case Result::kNotEnabled:
      env->ThrowError("realm time is not enabled");
      break;
    case Result::kNoActiveCall:
      env->ThrowError("there is no active external call");
      break;
    case Result::kOutOfOrder:
      env->ThrowError("external calls must be completed in LIFO order");
      break;
    case Result::kStaleGeneration:
      env->ThrowError("external call token belongs to a stale generation");
      break;
    case Result::kConflict:
      env->ThrowError(
          "external call completion conflicts with an earlier result");
      break;
    case Result::kInvalidDuration:
      env->ThrowRangeError(
          "functionDurationMs plus timelineAdjustmentMs must be finite and "
          "non-negative");
      break;
    case Result::kClockOverflow:
      env->ThrowRangeError("committed duration overflowed the virtual clock");
      break;
    case Result::kNotParked:
      env->ThrowError(
          "external call must be parked before it can be committed");
      break;
  }
  return false;
}

void EnableBinding(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  RealmTimeController* controller = ResolveController(args);
  if (controller == nullptr) return;
  if (!controller->Enable(RealWallTimeMilliseconds(env),
                          RealMonotonicTimeNanoseconds(),
                          env->event_loop())) {
    env->ThrowError(
        "this Worker already has a different Realm time controller enabled");
    return;
  }
  args.GetReturnValue().Set(true);
}

void DisableBinding(const FunctionCallbackInfo<Value>& args) {
  RealmTimeController* controller = ResolveController(args);
  if (controller == nullptr) return;
  controller->Disable();
  args.GetReturnValue().Set(true);
}

void IsEnabledBinding(const FunctionCallbackInfo<Value>& args) {
  RealmTimeController* controller = ResolveController(args);
  if (controller == nullptr) return;
  args.GetReturnValue().Set(controller->enabled());
}

void BeginExternalCallBinding(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  RealmTimeController* controller = ResolveController(args);
  if (controller == nullptr) return;
  if (!controller->enabled()) {
    env->ThrowError("realm time is not enabled");
    return;
  }
  std::string operation;
  if (!ReadOperation(env, args, &operation)) return;
  uint64_t token = controller->BeginExternalCall(RealWallTimeMilliseconds(env),
                                                 RealMonotonicTimeNanoseconds(),
                                                 std::move(operation));
  if (token == RealmTimeController::kInvalidToken) {
    env->ThrowError("failed to freeze the Worker timer clock");
    return;
  }
  args.GetReturnValue().Set(static_cast<double>(token));
}

void ParkExternalCallBinding(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  RealmTimeController* controller = ResolveController(args);
  if (controller == nullptr) return;
  if (args.Length() < 2) {
    env->ThrowTypeError("parkExternalCall requires context and token");
    return;
  }

  uint64_t token;
  if (!ReadToken(env, args[1], &token)) return;
  if (!ReturnTransactionResult(env, controller->ParkExternalCall(token))) {
    return;
  }
  args.GetReturnValue().Set(true);
}

void RequestExternalCallBinding(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  RealmTimeController* controller = ResolveController(args);
  if (controller == nullptr) return;
  if (args.Length() < 5) {
    env->ThrowTypeError(
        "requestExternalCall requires context, token, port, path, and body");
    return;
  }

  uint64_t token;
  if (!ReadToken(env, args[1], &token)) return;
  uint32_t port;
  if (!ReadControllerPort(env, args[2], &port)) return;
  std::string path;
  if (!ReadControllerPath(env, args[3], &path)) return;
  if (!args[4]->IsString()) {
    env->ThrowTypeError("body must be a string");
    return;
  }
  Utf8Value body_value(env->isolate(), args[4]);
  if (*body_value == nullptr) {
    env->ThrowError("failed to encode request body as UTF-8");
    return;
  }
  std::string body(*body_value, body_value.length());

  if (!ReturnTransactionResult(env, controller->ParkExternalCall(token))) {
    return;
  }

  ControllerHttpResponse response;
  if (!PerformControllerPost(env,
                             port,
                             path,
                             body,
                             token,
                             TokenGeneration(token),
                             &response)) {
    return;
  }

  Isolate* isolate = args.GetIsolate();
  Local<Context> context = isolate->GetCurrentContext();
  Local<Object> result = Object::New(isolate);
  result
      ->Set(context,
            OneByteString(isolate, "statusCode"),
            Integer::New(isolate, response.status_code))
      .Check();
  Local<String> response_body_value;
  if (!String::NewFromUtf8(isolate,
                           response.body.data(),
                           v8::NewStringType::kNormal,
                           static_cast<int>(response.body.size()))
           .ToLocal(&response_body_value)) {
    return;
  }
  result->Set(context, OneByteString(isolate, "body"), response_body_value)
      .Check();
  args.GetReturnValue().Set(result);
}

void CommitExternalCallBinding(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  RealmTimeController* controller = ResolveController(args);
  if (controller == nullptr) return;
  if (args.Length() < 3) {
    env->ThrowTypeError(
        "commitExternalCall requires context, token, and functionDurationMs");
    return;
  }

  uint64_t token;
  double function_duration_ms;
  double timeline_adjustment_ms = 0;
  if (!ReadToken(env, args[1], &token) ||
      !ReadDuration(env, args[2], &function_duration_ms) ||
      (args.Length() >= 4 &&
       !ReadAdjustment(env, args[3], &timeline_adjustment_ms))) {
    return;
  }

  if (!ReturnTransactionResult(
          env,
          controller->CommitExternalCall(token,
                                         function_duration_ms,
                                         timeline_adjustment_ms,
                                         RealWallTimeMilliseconds(env),
                                         RealMonotonicTimeNanoseconds()))) {
    return;
  }
  args.GetReturnValue().Set(true);
}

void AbortExternalCallBinding(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  RealmTimeController* controller = ResolveController(args);
  if (controller == nullptr) return;
  if (args.Length() < 2) {
    env->ThrowTypeError("abortExternalCall requires context and token");
    return;
  }

  uint64_t token;
  if (!ReadToken(env, args[1], &token)) return;
  if (!ReturnTransactionResult(
          env,
          controller->AbortExternalCall(token,
                                        RealWallTimeMilliseconds(env),
                                        RealMonotonicTimeNanoseconds()))) {
    return;
  }
  args.GetReturnValue().Set(true);
}

Local<Object> ClockTraceStatsToObject(Environment* env) {
  Isolate* isolate = env->isolate();
  Local<Context> context = isolate->GetCurrentContext();
  ClockTraceState& trace = ClockTrace();
  std::lock_guard<std::mutex> lock(trace.mutex);
  Local<Object> result = Object::New(isolate);
  auto set = [&](const char* name, Local<Value> value) {
    result->Set(context, OneByteString(isolate, name), value).Check();
  };
  set("enabled", Boolean::New(isolate, trace.enabled.load()));
  set("capacity", Number::New(isolate, static_cast<double>(trace.ring.size())));
  set("pending", Number::New(isolate, static_cast<double>(trace.count)));
  set("dropped", Number::New(isolate, static_cast<double>(trace.dropped)));
  set("total", Number::New(isolate, static_cast<double>(trace.total)));
  return result;
}

// startClockTrace({ capacity? }): (re)initialises the ring and turns tracing
// on.  A restart discards whatever was pending.
void StartClockTraceBinding(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Isolate* isolate = env->isolate();
  Local<Context> context = isolate->GetCurrentContext();
  size_t capacity = kClockTraceDefaultCapacity;
  if (args.Length() > 0 && !args[0]->IsUndefined()) {
    if (!args[0]->IsObject()) {
      env->ThrowTypeError("startClockTrace options must be an object");
      return;
    }
    Local<Value> value;
    if (!args[0].As<Object>()
             ->Get(context, OneByteString(isolate, "capacity"))
             .ToLocal(&value)) {
      return;
    }
    if (!value->IsUndefined()) {
      if (!value->IsNumber()) {
        env->ThrowTypeError("capacity must be a number");
        return;
      }
      const double requested = value.As<Number>()->Value();
      if (!std::isfinite(requested) || requested < 1 ||
          requested != std::floor(requested) ||
          requested > static_cast<double>(kClockTraceMaxCapacity)) {
        env->ThrowRangeError("capacity must be a whole number in 1..2^24");
        return;
      }
      capacity = static_cast<size_t>(requested);
    }
  }
  ClockTraceState& trace = ClockTrace();
  {
    std::lock_guard<std::mutex> lock(trace.mutex);
    trace.ring.assign(capacity, ClockTraceRecord{});
    trace.head = 0;
    trace.count = 0;
    trace.next_seq = 0;
    trace.dropped = 0;
    trace.total = 0;
    trace.start_ns = uv_hrtime();
    trace.enabled.store(true, std::memory_order_release);
  }
  args.GetReturnValue().Set(ClockTraceStatsToObject(env));
}

void StopClockTraceBinding(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  ClockTrace().enabled.store(false, std::memory_order_release);
  args.GetReturnValue().Set(ClockTraceStatsToObject(env));
}

void ClockTraceStatsBinding(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  args.GetReturnValue().Set(ClockTraceStatsToObject(env));
}

// drainClockTrace(): moves every pending record out as columnar typed arrays
// (seq, kind, realMs since trace start, value, aux0, aux1) and resets the
// drop counter.  Columnar keeps a 65k drain cheap.
void DrainClockTraceBinding(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Isolate* isolate = env->isolate();
  Local<Context> context = isolate->GetCurrentContext();

  std::vector<ClockTraceRecord> records;
  uint64_t dropped = 0;
  uint64_t total = 0;
  uint64_t start_ns = 0;
  {
    ClockTraceState& trace = ClockTrace();
    std::lock_guard<std::mutex> lock(trace.mutex);
    records.reserve(trace.count);
    const size_t capacity = trace.ring.size();
    if (capacity != 0) {
      size_t index = (trace.head + capacity - trace.count) % capacity;
      for (size_t i = 0; i < trace.count; i++) {
        records.push_back(trace.ring[index]);
        index = (index + 1) % capacity;
      }
    }
    dropped = trace.dropped;
    total = trace.total;
    start_ns = trace.start_ns;
    trace.head = 0;
    trace.count = 0;
    trace.dropped = 0;
  }

  const size_t n = records.size();
  auto make_f64 = [&](auto getter) {
    Local<ArrayBuffer> buffer =
        ArrayBuffer::New(isolate, n * sizeof(double));
    double* data = static_cast<double*>(buffer->Data());
    for (size_t i = 0; i < n; i++) data[i] = getter(records[i]);
    return Float64Array::New(buffer, 0, n);
  };
  Local<ArrayBuffer> kind_buffer = ArrayBuffer::New(isolate, n);
  uint8_t* kind_data = static_cast<uint8_t*>(kind_buffer->Data());
  for (size_t i = 0; i < n; i++) kind_data[i] = records[i].kind;

  Local<Object> result = Object::New(isolate);
  auto set = [&](const char* name, Local<Value> value) {
    result->Set(context, OneByteString(isolate, name), value).Check();
  };
  set("count", Number::New(isolate, static_cast<double>(n)));
  set("seq", make_f64([](const ClockTraceRecord& r) {
        return static_cast<double>(r.seq);
      }));
  set("kind", Uint8Array::New(kind_buffer, 0, n));
  set("realMs", make_f64([start_ns](const ClockTraceRecord& r) {
        return (static_cast<double>(r.real_ns) -
                static_cast<double>(start_ns)) / 1e6;
      }));
  set("value", make_f64([](const ClockTraceRecord& r) { return r.value; }));
  set("aux0", make_f64([](const ClockTraceRecord& r) { return r.aux0; }));
  set("aux1", make_f64([](const ClockTraceRecord& r) { return r.aux1; }));
  set("dropped", Number::New(isolate, static_cast<double>(dropped)));
  set("total", Number::New(isolate, static_cast<double>(total)));
  args.GetReturnValue().Set(result);
}

Local<Object> ClockRulesToObject(Environment* env) {
  Isolate* isolate = env->isolate();
  Local<Context> context = isolate->GetCurrentContext();
  ClockRulesState& rules = ClockRules();
  Local<Object> result = Object::New(isolate);
  result
      ->Set(context,
            OneByteString(isolate, "performanceNowOffsetMs"),
            Number::New(isolate, rules.performance_now_offset_ms.load()))
      .Check();
  result
      ->Set(context,
            OneByteString(isolate, "dateOffsetMs"),
            Number::New(isolate, rules.date_offset_ms.load()))
      .Check();
  return result;
}

void GetClockRulesBinding(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  args.GetReturnValue().Set(ClockRulesToObject(env));
}

// setClockRules({ performanceNowOffsetMs?, dateOffsetMs? }): undefined keeps
// the current value; non-finite numbers throw.
void SetClockRulesBinding(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Isolate* isolate = env->isolate();
  Local<Context> context = isolate->GetCurrentContext();
  if (args.Length() < 1 || !args[0]->IsObject()) {
    env->ThrowTypeError("setClockRules requires an options object");
    return;
  }
  Local<Object> options = args[0].As<Object>();
  ClockRulesState& rules = ClockRules();
  double performance_now_offset_ms = rules.performance_now_offset_ms.load();
  double date_offset_ms = rules.date_offset_ms.load();
  Local<Value> value;

  if (!options->Get(context, OneByteString(isolate, "performanceNowOffsetMs"))
           .ToLocal(&value)) {
    return;
  }
  if (!value->IsUndefined()) {
    if (!value->IsNumber()) {
      env->ThrowTypeError("performanceNowOffsetMs must be a number");
      return;
    }
    performance_now_offset_ms = value.As<Number>()->Value();
    if (!std::isfinite(performance_now_offset_ms)) {
      env->ThrowRangeError("performanceNowOffsetMs must be finite");
      return;
    }
  }
  if (!options->Get(context, OneByteString(isolate, "dateOffsetMs"))
           .ToLocal(&value)) {
    return;
  }
  if (!value->IsUndefined()) {
    if (!value->IsNumber()) {
      env->ThrowTypeError("dateOffsetMs must be a number");
      return;
    }
    date_offset_ms = value.As<Number>()->Value();
    if (!std::isfinite(date_offset_ms)) {
      env->ThrowRangeError("dateOffsetMs must be finite");
      return;
    }
  }
  rules.performance_now_offset_ms.store(performance_now_offset_ms);
  rules.date_offset_ms.store(date_offset_ms);
  args.GetReturnValue().Set(ClockRulesToObject(env));
}

Local<Object> ClockSurfaceToObject(Environment* env,
                                   const ClockSurfaceSettings& settings) {
  Isolate* isolate = env->isolate();
  Local<Context> context = isolate->GetCurrentContext();
  Local<Object> result = Object::New(isolate);
  result
      ->Set(context,
            OneByteString(isolate, "resolutionNs"),
            Number::New(isolate, static_cast<double>(settings.resolution_ns)))
      .Check();
  result
      ->Set(context,
            OneByteString(isolate, "nestingClamp"),
            Boolean::New(isolate, settings.nesting_clamp))
      .Check();
  result
      ->Set(context,
            OneByteString(isolate, "timerGridMs"),
            Number::New(isolate, settings.timer_grid_ms))
      .Check();
  result
      ->Set(context,
            OneByteString(isolate, "highResolutionTimer"),
            Boolean::New(isolate, settings.high_resolution_timer))
      .Check();
  result
      ->Set(context,
            OneByteString(isolate, "platformTimerResolutionMs"),
            Number::New(isolate, PlatformTimerResolutionMs()))
      .Check();
  return result;
}

// The vm.Context behind a contextified sandbox object.  Frame-boundary callers
// always name a context: unlike the clock there is nothing useful to do with
// "whichever context we happen to be in".
bool ResolveContextArgument(const FunctionCallbackInfo<Value>& args,
                            Local<Context>* out) {
  Environment* env = Environment::GetCurrent(args);
  if (args.Length() == 0 || !args[0]->IsObject()) {
    env->ThrowTypeError("context must be a contextified vm object");
    return false;
  }
  contextify::ContextifyContext* contextify =
      contextify::ContextifyContext::ContextFromContextifiedSandbox(
          env, args[0].As<Object>());
  if (contextify == nullptr) {
    env->ThrowTypeError("context must be a contextified vm object");
    return false;
  }
  *out = contextify->context();
  return true;
}

// A context is a frame boundary exactly when it no longer shares the main
// context's security token.
bool IsFrameBoundary(Environment* env, Local<Context> context) {
  return !context->GetSecurityToken()->StrictEquals(
      env->context()->GetSecurityToken());
}

// setFrameBoundary(sandbox, enabled): hand the context its own security token,
// or give the main context's back.
//
// V8 already drops stack frames whose native context holds a different security
// token than the context capturing the stack (`VisitStack` in
// src/execution/isolate.cc; the filter is live because `StackTrace::kDetailed`
// does not carry kExposeFramesAcrossSecurityOrigins).  That is how a browser
// keeps one realm's frames out of another realm's `Error.stack`.  Node defeats
// it by handing every vm.Context the main context's token
// (node_contextify.cc), which is why code under vm.runInContext sees
// `at Script.runInContext (node:vm)` and host file paths in its own stacks.
// Dropping the shared token restores the browser behaviour for that context.
//
// Nothing else in Node reads the token: contextify installs no access-check
// callback, so it is not consulted for property access across the boundary.
//
// The filter runs while a stack is captured, not while it is formatted, so code
// inside the context sees only its own frames even if it installs its own
// `Error.prepareStackTrace` to read CallSite objects directly.
void SetFrameBoundaryBinding(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Local<Context> context;
  if (!ResolveContextArgument(args, &context)) return;
  if (args.Length() < 2 || !args[1]->IsBoolean()) {
    env->ThrowTypeError("enabled must be a boolean");
    return;
  }

  if (args[1]->BooleanValue(env->isolate())) {
    context->UseDefaultSecurityToken();
  } else {
    context->SetSecurityToken(env->context()->GetSecurityToken());
  }

  args.GetReturnValue().Set(IsFrameBoundary(env, context));
}

void GetFrameBoundaryBinding(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Local<Context> context;
  if (!ResolveContextArgument(args, &context)) return;
  args.GetReturnValue().Set(IsFrameBoundary(env, context));
}

void GetClockSurfaceBinding(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  args.GetReturnValue().Set(
      ClockSurfaceToObject(env, GetClockSurfaceSettings()));
}

// getReleaseInfo(): the release record compiled into this binary
// (src/rexmirror_release.h), the same one `node --version` prints.
void GetReleaseInfoBinding(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Isolate* isolate = env->isolate();
  Local<Context> context = env->context();
  Local<Object> result = Object::New(isolate);
  result
      ->Set(context,
            OneByteString(isolate, "serial"),
            Integer::New(isolate, REXMIRROR_RELEASE_SERIAL))
      .Check();
  result
      ->Set(context,
            OneByteString(isolate, "lyric"),
            OneByteString(isolate, REXMIRROR_RELEASE_LYRIC))
      .Check();
  result
      ->Set(context,
            OneByteString(isolate, "song"),
            OneByteString(isolate, REXMIRROR_RELEASE_SONG))
      .Check();
  result
      ->Set(context,
            OneByteString(isolate, "date"),
            OneByteString(isolate, REXMIRROR_RELEASE_DATE))
      .Check();
  args.GetReturnValue().Set(result);
}

// setClockSurface({ resolutionNs?, nestingClamp?, timerGridMs? }): fields
// left undefined keep their current value; anything else is validated here
// so a bad call throws instead of silently doing nothing.
void SetClockSurfaceBinding(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Isolate* isolate = env->isolate();
  Local<Context> context = isolate->GetCurrentContext();
  if (args.Length() < 1 || !args[0]->IsObject()) {
    env->ThrowTypeError("setClockSurface requires an options object");
    return;
  }
  Local<Object> options = args[0].As<Object>();
  ClockSurfaceSettings settings = GetClockSurfaceSettings();
  Local<Value> value;

  if (!options->Get(context, OneByteString(isolate, "resolutionNs"))
           .ToLocal(&value)) {
    return;
  }
  if (!value->IsUndefined()) {
    if (!value->IsNumber()) {
      env->ThrowTypeError("resolutionNs must be a number");
      return;
    }
    const double nanoseconds = value.As<Number>()->Value();
    if (!std::isfinite(nanoseconds) || nanoseconds < 0 ||
        nanoseconds != std::floor(nanoseconds) || nanoseconds > 1e12) {
      env->ThrowRangeError(
          "resolutionNs must be a whole number of nanoseconds in 0..1e12");
      return;
    }
    settings.resolution_ns = static_cast<int64_t>(nanoseconds);
  }

  if (!options->Get(context, OneByteString(isolate, "nestingClamp"))
           .ToLocal(&value)) {
    return;
  }
  if (!value->IsUndefined()) {
    if (!value->IsBoolean()) {
      env->ThrowTypeError("nestingClamp must be a boolean");
      return;
    }
    settings.nesting_clamp = value->IsTrue();
  }

  if (!options->Get(context, OneByteString(isolate, "timerGridMs"))
           .ToLocal(&value)) {
    return;
  }
  if (!value->IsUndefined()) {
    if (!value->IsNumber()) {
      env->ThrowTypeError("timerGridMs must be a number");
      return;
    }
    const double grid = value.As<Number>()->Value();
    if (!std::isfinite(grid) || grid < 0) {
      env->ThrowRangeError("timerGridMs must be finite and non-negative");
      return;
    }
    settings.timer_grid_ms = grid;
  }

  if (!options->Get(context, OneByteString(isolate, "highResolutionTimer"))
           .ToLocal(&value)) {
    return;
  }
  if (!value->IsUndefined()) {
    if (!value->IsBoolean()) {
      env->ThrowTypeError("highResolutionTimer must be a boolean");
      return;
    }
    settings.high_resolution_timer = value->IsTrue();
  }

  std::string error;
  if (!SetClockSurfaceSettings(settings, &error)) {
    env->ThrowRangeError(error.c_str());
    return;
  }
  args.GetReturnValue().Set(
      ClockSurfaceToObject(env, GetClockSurfaceSettings()));
}

void GetStateBinding(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  RealmTimeController* controller = ResolveController(args);
  if (controller == nullptr) return;

  Isolate* isolate = args.GetIsolate();
  Local<Context> context = isolate->GetCurrentContext();
  Local<Object> state = Object::New(isolate);
  auto set = [&](const char* name, Local<Value> value) {
    state->Set(context, OneByteString(isolate, name), value).Check();
  };

  const double real_wall_time_ms = RealWallTimeMilliseconds(env);
  const uint64_t real_monotonic_time_ns = RealMonotonicTimeNanoseconds();
  set("enabled", Boolean::New(isolate, controller->enabled()));
  set("frozen", Boolean::New(isolate, controller->frozen()));
  set("parked", Boolean::New(isolate, controller->parked()));
  set("generation",
      Number::New(isolate, static_cast<double>(controller->generation())));
  const char* phase = !controller->enabled()  ? "disabled"
                      : !controller->frozen() ? "running"
                      : controller->parked()  ? "parked"
                                              : "freezing";
  set("phase", OneByteString(isolate, phase));
  set("depth",
      Integer::NewFromUnsigned(isolate,
                               static_cast<uint32_t>(controller->depth())));
  set("dateNow",
      Number::New(isolate,
                  controller->CurrentWallTimeMilliseconds(real_wall_time_ms)));
  set("monotonicNow",
      Number::New(
          isolate,
          controller->CurrentMonotonicTimeNanoseconds(real_monotonic_time_ns) /
              kNanosecondsPerMillisecond));
  if (controller->active_token() == RealmTimeController::kInvalidToken) {
    set("activeToken", Null(isolate));
    set("operation", Null(isolate));
  } else {
    set("activeToken",
        Number::New(isolate, static_cast<double>(controller->active_token())));
    set("operation",
        String::NewFromUtf8(isolate,
                            controller->active_operation().c_str(),
                            v8::NewStringType::kNormal,
                            static_cast<int>(
                                controller->active_operation().size()))
            .ToLocalChecked());
  }
  args.GetReturnValue().Set(state);
}

void Initialize(Local<Object> target,
                Local<Value> unused,
                Local<Context> context,
                void* priv) {
  SetMethod(context, target, "enable", EnableBinding);
  SetMethod(context, target, "disable", DisableBinding);
  SetMethod(context, target, "isEnabled", IsEnabledBinding);
  SetMethod(context, target, "beginExternalCall", BeginExternalCallBinding);
  SetMethod(context, target, "parkExternalCall", ParkExternalCallBinding);
  SetMethod(context, target, "requestExternalCall", RequestExternalCallBinding);
  SetMethod(context, target, "commitExternalCall", CommitExternalCallBinding);
  SetMethod(context, target, "abortExternalCall", AbortExternalCallBinding);
  SetMethod(context, target, "getState", GetStateBinding);
  SetMethod(context,
            target,
            "setCodeGenerationCallback",
            SetCodeGenerationCallbackBinding);
  SetMethod(context,
            target,
            "setUncaughtExceptionCallback",
            SetUncaughtExceptionCallbackBinding);
  SetMethod(context,
            target,
            "getCodeGenerationRecords",
            GetCodeGenerationRecordsBinding);
  SetMethod(context, target, "getExceptionRecords", GetExceptionRecordsBinding);
  SetMethod(context, target, "getClockSurface", GetClockSurfaceBinding);
  SetMethod(context, target, "getReleaseInfo", GetReleaseInfoBinding);
  SetMethod(context, target, "setFrameBoundary", SetFrameBoundaryBinding);
  SetMethod(context, target, "getFrameBoundary", GetFrameBoundaryBinding);
  SetMethod(context, target, "setClockSurface", SetClockSurfaceBinding);
  SetMethod(context, target, "startClockTrace", StartClockTraceBinding);
  SetMethod(context, target, "stopClockTrace", StopClockTraceBinding);
  SetMethod(context, target, "drainClockTrace", DrainClockTraceBinding);
  SetMethod(context, target, "clockTraceStats", ClockTraceStatsBinding);
  SetMethod(context, target, "getClockRules", GetClockRulesBinding);
  SetMethod(context, target, "setClockRules", SetClockRulesBinding);
}

}  // namespace

bool ApplyCodeGenerationCallback(Environment* env,
                                 Local<Context> target_context,
                                 const char* kind,
                                 Local<String> source,
                                 Local<v8::Array> parameters,
                                 Local<Value> resource_name,
                                 Local<String>* result) {
  *result = source;
  DiagnosticsState* state = GetDiagnosticsState(env, false);
  if (state == nullptr || state->code_generation_callback.IsEmpty() ||
      state->in_codegen_callback || !env->can_call_into_js()) {
    return true;
  }
  if (!state->include_vm_compile && std::string_view(kind).starts_with("vm.")) {
    return true;
  }

  Isolate* isolate = env->isolate();
  if (!state->code_generation_target_context.IsEmpty() &&
      state->code_generation_target_context.Get(isolate) != target_context) {
    return true;
  }
  CallerLocation caller = GetCallerLocation(isolate);
  const uint64_t codegen_id = NextSafeSequence(&state->next_codegen_id);
  const uint64_t host_monotonic_ns = uv_hrtime();
  const int context_id = target_context->Global()->GetIdentityHash();
  const std::string source_hash = Sha256(source);
  const size_t source_length = static_cast<size_t>(source->Length());

  CodeGenerationRecord record{
      .id = codegen_id,
      .kind = kind,
      .source_hash = source_hash,
      .root_source_id = state->root_source_id,
      .context_id = context_id,
      .parent_script_id = caller.script_id,
      .caller_line = caller.line,
      .caller_column = caller.column,
      .worker_id = env->thread_id(),
      .host_monotonic_ns = host_monotonic_ns,
      .source_length = source_length,
  };

  Local<Context> callback_context = state->code_generation_context.Get(isolate);
  Local<Function> callback = state->code_generation_callback.Get(isolate);
  if (callback_context.IsEmpty() || callback.IsEmpty()) return true;

  Context::Scope callback_scope(callback_context);
  Local<Object> info = Object::New(isolate);
  SetDiagnosticProperty(
      callback_context, info, "codegenId", Number::New(isolate, codegen_id));
  SetDiagnosticProperty(
      callback_context, info, "kind", OneByteString(isolate, kind));
  SetDiagnosticProperty(callback_context, info, "source", source);
  SetDiagnosticProperty(callback_context, info, "parameters", parameters);
  SetDiagnosticProperty(callback_context,
                        info,
                        "sourceHash",
                        DiagnosticString(isolate, source_hash));
  SetDiagnosticProperty(
      callback_context,
      info,
      "realmGeneration",
      Number::New(isolate,
                  GetController(target_context) == nullptr
                      ? 0
                      : GetController(target_context)->generation()));
  SetDiagnosticProperty(
      callback_context, info, "contextId", Integer::New(isolate, context_id));
  SetDiagnosticProperty(callback_context,
                        info,
                        "workerId",
                        Number::New(isolate, env->thread_id()));
  SetDiagnosticProperty(
      callback_context,
      info,
      "parentScriptId",
      caller.script_id == Message::kNoScriptIdInfo
          ? Null(isolate).As<Value>()
          : Integer::New(isolate, caller.script_id).As<Value>());
  SetDiagnosticProperty(
      callback_context, info, "parentCodegenId", Null(isolate));
  SetDiagnosticProperty(callback_context,
                        info,
                        "rootSourceId",
                        DiagnosticString(isolate, state->root_source_id));
  SetDiagnosticProperty(
      callback_context, info, "callerLine", Integer::New(isolate, caller.line));
  SetDiagnosticProperty(callback_context,
                        info,
                        "callerColumn",
                        Integer::New(isolate, caller.column));
  Local<Value> source_url = resource_name;
  if (source_url.IsEmpty() || source_url->IsUndefined()) {
    const std::string extracted_source_url = ExtractSourceURL(source);
    if (!extracted_source_url.empty()) {
      source_url = DiagnosticString(isolate, extracted_source_url);
    } else {
      source_url = caller.script_name.IsEmpty()
                       ? Null(isolate).As<Value>()
                       : caller.script_name.As<Value>();
    }
  }
  SetDiagnosticProperty(callback_context, info, "sourceURL", source_url);
  SetDiagnosticProperty(
      callback_context,
      info,
      "hostMonotonicNs",
      v8::BigInt::NewFromUnsigned(isolate, host_monotonic_ns));
  SetDiagnosticProperty(callback_context,
                        info,
                        "compileResult",
                        OneByteString(isolate, "attempt"));

  Local<Object> control_data = Object::New(isolate);
  SetDiagnosticProperty(
      callback_context, control_data, "active", Boolean::New(isolate, true));
  SetDiagnosticProperty(
      callback_context, control_data, "replacement", Undefined(isolate));
  Local<Object> control = Object::New(isolate);
  Local<Function> replace_source =
      Function::New(callback_context, ReplaceSourceControl, control_data)
          .ToLocalChecked();
  SetDiagnosticProperty(
      callback_context, control, "replaceSource", replace_source);

  v8::TryCatch try_catch(isolate);
  try_catch.SetVerbose(false);
  Local<Value> argv[2] = {info, control};
  state->in_codegen_callback = true;
  MaybeLocal<Value> maybe_callback_result = callback->Call(
      callback_context, Undefined(isolate), arraysize(argv), argv);
  state->in_codegen_callback = false;
  SetDiagnosticProperty(
      callback_context, control_data, "active", Boolean::New(isolate, false));

  if (maybe_callback_result.IsEmpty()) {
    record.callback_error = true;
    try_catch.Reset();
  } else {
    Local<Value> replacement;
    if (control_data
            ->Get(callback_context, OneByteString(isolate, "replacement"))
            .ToLocal(&replacement) &&
        replacement->IsString()) {
      Utf8Value replacement_text(isolate, replacement);
      Local<String> flattened_replacement;
      if (*replacement_text != nullptr &&
          String::NewFromUtf8(isolate,
                              *replacement_text,
                              v8::NewStringType::kNormal,
                              replacement_text.length())
              .ToLocal(&flattened_replacement)) {
        *result = flattened_replacement;
        record.replaced = true;
      }
    }
  }

  if (state->code_generation_records.size() == kDiagnosticsRecordLimit) {
    state->code_generation_records.pop_front();
  }
  state->code_generation_records.push_back(std::move(record));
  return true;
}

v8::ModifyCodeGenerationFromStringsResult ModifyCodeGenerationFromStrings(
    Environment* env,
    Local<Context> context,
    Local<Value> source,
    bool is_code_like,
    bool codegen_allowed) {
  if (!codegen_allowed || !source->IsString()) {
    return {codegen_allowed, {}};
  }
  Isolate* isolate = env->isolate();
  EscapableHandleScope scope(isolate);
  Local<String> original = source.As<String>();
  const std::string kind = ClassifyStringCodeGeneration(original);
  Local<String> replacement;
  if (!ApplyCodeGenerationCallback(env,
                                   context,
                                   kind.c_str(),
                                   original,
                                   v8::Array::New(isolate),
                                   Undefined(isolate),
                                   &replacement)) {
    return {false, {}};
  }
  if (replacement == original) return {true, {}};
  return {true, scope.Escape(replacement)};
}

Local<Value> InterceptUncaughtException(Environment* env,
                                        Local<Value> exception,
                                        Local<Message> message,
                                        bool from_promise) {
  Isolate* isolate = env->isolate();
  EscapableHandleScope scope(isolate);
  DiagnosticsState* state = GetDiagnosticsState(env, false);
  if (state == nullptr || state->exception_callback.IsEmpty() ||
      state->in_exception_callback || !env->can_call_into_js() ||
      (from_promise && !state->include_confirmed_unhandled_rejection)) {
    return scope.Escape(exception);
  }

  Local<Context> target_context = isolate->GetCurrentContext();
  Local<Context> realm_context =
      state->exception_target_context.IsEmpty()
          ? target_context
          : state->exception_target_context.Get(isolate);
  Local<Context> callback_context = state->exception_context.Get(isolate);
  Local<Function> callback = state->exception_callback.Get(isolate);
  if (callback_context.IsEmpty() || callback.IsEmpty()) {
    return scope.Escape(exception);
  }

  const uint64_t exception_id = NextSafeSequence(&state->next_exception_id);
  const uint64_t host_monotonic_ns = uv_hrtime();
  const char* origin =
      from_promise ? "unhandledRejection" : "uncaughtException";
  const int script_id = message->GetScriptOrigin().ScriptId();
  const int line = message->GetLineNumber(target_context).FromMaybe(0);
  const int column = message->GetStartColumn();
  Local<Value> exception_source_url = message->GetScriptResourceName();
  if (exception_source_url.IsEmpty()) {
    exception_source_url = Null(isolate);
  }
  Local<String> exception_script_name = exception_source_url->IsString()
                                            ? exception_source_url.As<String>()
                                            : String::Empty(isolate);
  RealmTimeController* controller = GetController(realm_context);
  if (controller == nullptr) controller = GetCurrentController(isolate);
  if (controller == nullptr &&
      process_clock.enabled.load(std::memory_order_acquire)) {
    controller = const_cast<RealmTimeController*>(
        process_clock.owner.load(std::memory_order_acquire));
  }

  ExceptionRecord record{
      .id = exception_id,
      .origin = origin,
      .root_source_id = state->root_source_id,
      .context_id = realm_context->Global()->GetIdentityHash(),
      .script_id = script_id,
      .line = line,
      .column = column,
      .worker_id = env->thread_id(),
      .host_monotonic_ns = host_monotonic_ns,
  };

  Context::Scope callback_scope(callback_context);
  Local<Object> info = Object::New(isolate);
  SetDiagnosticProperty(callback_context,
                        info,
                        "exceptionId",
                        Number::New(isolate, exception_id));
  SetDiagnosticProperty(
      callback_context, info, "origin", OneByteString(isolate, origin));
  SetDiagnosticProperty(
      callback_context,
      info,
      "realmGeneration",
      Number::New(isolate,
                  controller == nullptr ? 0 : controller->generation()));
  SetDiagnosticProperty(
      callback_context,
      info,
      "transactionId",
      controller == nullptr ||
              controller->active_token() == RealmTimeController::kInvalidToken
          ? Null(isolate).As<Value>()
          : Number::New(isolate, controller->active_token()).As<Value>());
  SetDiagnosticProperty(callback_context,
                        info,
                        "contextId",
                        Integer::New(isolate, record.context_id));
  SetDiagnosticProperty(callback_context,
                        info,
                        "workerId",
                        Number::New(isolate, env->thread_id()));
  SetDiagnosticProperty(callback_context,
                        info,
                        "executionAsyncId",
                        Number::New(isolate, env->execution_async_id()));
  SetDiagnosticProperty(callback_context,
                        info,
                        "triggerAsyncId",
                        Number::New(isolate, env->trigger_async_id()));
  SetDiagnosticProperty(
      callback_context, info, "scriptId", Integer::New(isolate, script_id));
  SetDiagnosticProperty(callback_context,
                        info,
                        "parentSourceId",
                        script_id == Message::kNoScriptIdInfo
                            ? Null(isolate).As<Value>()
                            : Integer::New(isolate, script_id).As<Value>());
  SetDiagnosticProperty(callback_context,
                        info,
                        "rootSourceId",
                        DiagnosticString(isolate, state->root_source_id));
  SetDiagnosticProperty(
      callback_context, info, "line", Integer::New(isolate, line));
  SetDiagnosticProperty(
      callback_context, info, "column", Integer::New(isolate, column));
  SetDiagnosticProperty(
      callback_context, info, "sourceURL", exception_source_url);
  SetDiagnosticProperty(
      callback_context,
      info,
      "hostMonotonicNs",
      v8::BigInt::NewFromUnsigned(isolate, host_monotonic_ns));
  const uint64_t realm_time_ns = static_cast<uint64_t>(
      std::max(0.0, CurrentMonotonicTimeNanoseconds(host_monotonic_ns)));
  SetDiagnosticProperty(callback_context,
                        info,
                        "realmTimeNs",
                        v8::BigInt::NewFromUnsigned(isolate, realm_time_ns));
  SetDiagnosticProperty(
      callback_context, info, "handled", Boolean::New(isolate, false));
  SetDiagnosticProperty(callback_context,
                        info,
                        "escalatedFromRejection",
                        Boolean::New(isolate, from_promise));

  Local<StackTrace> stack = Exception::GetStackTrace(exception);
  if (stack.IsEmpty()) stack = message->GetStackTrace();
  const int frame_count = stack.IsEmpty() ? 0 : stack->GetFrameCount();
  Local<v8::Array> frames =
      v8::Array::New(isolate, frame_count == 0 ? 1 : frame_count);
  if (frame_count == 0) {
    Local<Object> frame_info = Object::New(isolate);
    SetDiagnosticProperty(callback_context,
                          frame_info,
                          "scriptId",
                          Integer::New(isolate, script_id));
    SetDiagnosticProperty(
        callback_context, frame_info, "line", Integer::New(isolate, line));
    SetDiagnosticProperty(
        callback_context, frame_info, "column", Integer::New(isolate, column));
    SetDiagnosticProperty(
        callback_context, frame_info, "functionName", String::Empty(isolate));
    SetDiagnosticProperty(
        callback_context, frame_info, "scriptName", exception_script_name);
    frames->Set(callback_context, 0, frame_info).Check();
  }
  for (int index = 0; index < frame_count; index++) {
    Local<StackFrame> frame = stack->GetFrame(isolate, index);
    Local<Object> frame_info = Object::New(isolate);
    SetDiagnosticProperty(callback_context,
                          frame_info,
                          "scriptId",
                          Integer::New(isolate, frame->GetScriptId()));
    SetDiagnosticProperty(callback_context,
                          frame_info,
                          "line",
                          Integer::New(isolate, frame->GetLineNumber()));
    SetDiagnosticProperty(callback_context,
                          frame_info,
                          "column",
                          Integer::New(isolate, frame->GetColumn()));
    SetDiagnosticProperty(
        callback_context, frame_info, "functionName", frame->GetFunctionName());
    SetDiagnosticProperty(
        callback_context, frame_info, "scriptName", frame->GetScriptName());
    frames->Set(callback_context, index, frame_info).Check();
  }
  SetDiagnosticProperty(callback_context, info, "frames", frames);

  Local<Object> control_data = Object::New(isolate);
  SetDiagnosticProperty(
      callback_context, control_data, "active", Boolean::New(isolate, true));
  SetDiagnosticProperty(callback_context,
                        control_data,
                        "hasReplacement",
                        Boolean::New(isolate, false));
  SetDiagnosticProperty(
      callback_context, control_data, "replacement", Undefined(isolate));
  Local<Object> control = Object::New(isolate);
  Local<Function> replace =
      Function::New(callback_context, ReplaceExceptionControl, control_data)
          .ToLocalChecked();
  SetDiagnosticProperty(callback_context, control, "replace", replace);

  v8::TryCatch try_catch(isolate);
  try_catch.SetVerbose(false);
  Local<Value> argv[3] = {exception, info, control};
  state->in_exception_callback = true;
  MaybeLocal<Value> maybe_callback_result = callback->Call(
      callback_context, Undefined(isolate), arraysize(argv), argv);
  state->in_exception_callback = false;
  SetDiagnosticProperty(
      callback_context, control_data, "active", Boolean::New(isolate, false));

  Local<Value> result = exception;
  if (maybe_callback_result.IsEmpty()) {
    record.callback_error = true;
    try_catch.Reset();
  } else {
    Local<Value> has_replacement;
    if (control_data
            ->Get(callback_context, OneByteString(isolate, "hasReplacement"))
            .ToLocal(&has_replacement) &&
        has_replacement->IsTrue()) {
      Local<Value> replacement;
      if (control_data
              ->Get(callback_context, OneByteString(isolate, "replacement"))
              .ToLocal(&replacement)) {
        result = replacement;
        record.replaced = true;
      }
    }
  }

  if (state->exception_records.size() == kDiagnosticsRecordLimit) {
    state->exception_records.pop_front();
  }
  state->exception_records.push_back(std::move(record));
  return scope.Escape(result);
}

bool RealmTimeController::Enable(double real_wall_time_ms,
                                 uint64_t real_monotonic_time_ns,
                                 uv_loop_t* event_loop) {
  if (event_loop == nullptr) return false;
  if (enabled_) Disable();
  if (uv_realm_time_enable(event_loop, this) != 0) return false;
  if (!EnableProcessClock(this)) {
    uv_realm_time_disable(event_loop, this);
    return false;
  }

  constexpr uint64_t kMaxGeneration =
      (kMaxSafeInteger - 1) / kTokenSequenceStride;
  generation_ = generation_ >= kMaxGeneration ? 1 : generation_ + 1;
  next_sequence_ = 0;
  event_loop_ = event_loop;
  enabled_ = true;
  wall_time_offset_ms_ = 0;
  monotonic_time_offset_ns_ = 0;
  frozen_wall_time_ms_ = real_wall_time_ms;
  frozen_monotonic_time_ns_ = real_monotonic_time_ns;
  frames_.clear();
  completed_calls_.clear();
  return true;
}

void RealmTimeController::Disable() {
  if (enabled_ && event_loop_ != nullptr) {
    uv_realm_time_disable(event_loop_, this);
  }
  DisableProcessClock(this);
  enabled_ = false;
  event_loop_ = nullptr;
  wall_time_offset_ms_ = 0;
  monotonic_time_offset_ns_ = 0;
  frozen_wall_time_ms_ = 0;
  frozen_monotonic_time_ns_ = 0;
  frames_.clear();
  completed_calls_.clear();
}

uint64_t RealmTimeController::NextToken() {
  if (next_sequence_ + 1 >= kTokenSequenceStride) return kInvalidToken;
  return generation_ * kTokenSequenceStride + ++next_sequence_;
}

uint64_t RealmTimeController::BeginExternalCall(double real_wall_time_ms,
                                                uint64_t real_monotonic_time_ns,
  std::string operation) {
  if (!enabled_) return kInvalidToken;
  if (frames_.empty()) {
    frozen_wall_time_ms_ = CurrentWallTimeMilliseconds(real_wall_time_ms);
    frozen_monotonic_time_ns_ =
        CurrentMonotonicTimeNanoseconds(real_monotonic_time_ns);
    if (!FreezeProcessClock(
            this, frozen_wall_time_ms_, frozen_monotonic_time_ns_)) {
      return kInvalidToken;
    }
    if (uv_realm_time_freeze(event_loop_, this) != 0) {
      ResumeProcessClock(this,
                         frozen_wall_time_ms_ - real_wall_time_ms,
                         frozen_monotonic_time_ns_ -
                             static_cast<double>(real_monotonic_time_ns));
      return kInvalidToken;
    }
  }
  uint64_t token = NextToken();
  if (token == kInvalidToken) {
    if (frames_.empty()) {
      uv_realm_time_resume(event_loop_, this, 0);
      ResumeProcessClock(this,
                         frozen_wall_time_ms_ - real_wall_time_ms,
                         frozen_monotonic_time_ns_ -
                             static_cast<double>(real_monotonic_time_ns));
    }
    return kInvalidToken;
  }
  frames_.push_back({token, std::move(operation), false, 0});
  return token;
}

RealmTimeController::TransactionResult RealmTimeController::ParkExternalCall(
    uint64_t token) {
  if (!enabled_) return TransactionResult::kNotEnabled;
  if (!TokenHasCurrentGeneration(token)) {
    return TransactionResult::kStaleGeneration;
  }
  if (frames_.empty()) return TransactionResult::kNoActiveCall;
  if (frames_.back().token != token) return TransactionResult::kOutOfOrder;
  if (frames_.back().parked) return TransactionResult::kIdempotent;
  frames_.back().parked = true;
  return TransactionResult::kOk;
}

RealmTimeController::TransactionResult RealmTimeController::CommitExternalCall(
    uint64_t token,
    double function_duration_ms,
    double timeline_adjustment_ms,
    double real_wall_time_ms,
    uint64_t real_monotonic_time_ns) {
  if (!enabled_) return TransactionResult::kNotEnabled;
  if (!TokenHasCurrentGeneration(token)) {
    return TransactionResult::kStaleGeneration;
  }
  TransactionResult completed =
      FindCompleted(token, true, function_duration_ms, timeline_adjustment_ms);
  if (completed != TransactionResult::kNoActiveCall) return completed;
  if (frames_.empty()) return TransactionResult::kNoActiveCall;
  if (frames_.back().token != token) return TransactionResult::kOutOfOrder;
  if (!frames_.back().parked) return TransactionResult::kNotParked;

  double own_duration_ms = function_duration_ms + timeline_adjustment_ms;
  if (!std::isfinite(function_duration_ms) || function_duration_ms < 0 ||
      !std::isfinite(timeline_adjustment_ms) ||
      !std::isfinite(own_duration_ms) || own_duration_ms < 0) {
    return TransactionResult::kInvalidDuration;
  }

  double committed_duration_ms =
      frames_.back().committed_duration_ms + own_duration_ms;
  if (!std::isfinite(committed_duration_ms)) {
    return TransactionResult::kClockOverflow;
  }

  // An inner transaction never owns the process release boundary.  Its
  // browser function duration is still a synchronous phase, so keep the
  // event loop parked while the caller's native stack simulates that work;
  // the accumulated logical duration is applied exactly once by the outer
  // transaction.
  if (frames_.size() > 1) {
    WaitFunctionDuration(function_duration_ms);
    frames_[frames_.size() - 2].committed_duration_ms =
        frames_[frames_.size() - 2].committed_duration_ms +
        committed_duration_ms;
    if (!std::isfinite(frames_[frames_.size() - 2].committed_duration_ms)) {
      return TransactionResult::kClockOverflow;
    }
    frames_.pop_back();
    RememberCompletion(token, true, function_duration_ms,
                       timeline_adjustment_ms);
    return TransactionResult::kOk;
  }

  // Go has already ended the OS suspension before returning the response.
  // Simulate the browser function stage on this native stack, then atomically
  // project its logical duration without allowing target event-loop re-entry.
  WaitFunctionDuration(function_duration_ms);
  // The binding captures its arguments before entering this method.  The wait
  // makes those timestamps stale; reconstruct the current wall timestamp so
  // real wait time is not counted a second time after the logical duration.
  const uint64_t resume_real_monotonic_time_ns = uv_hrtime();
  const double elapsed_real_ms =
      resume_real_monotonic_time_ns >= real_monotonic_time_ns
          ? static_cast<double>(resume_real_monotonic_time_ns -
                                real_monotonic_time_ns) /
                kNanosecondsPerMillisecond
          : 0;
  const double resume_real_wall_time_ms = real_wall_time_ms + elapsed_real_ms;
  if (!Resume(committed_duration_ms,
              resume_real_wall_time_ms,
              resume_real_monotonic_time_ns)) {
    return TransactionResult::kClockOverflow;
  }

  frames_.pop_back();
  RememberCompletion(token, true, function_duration_ms, timeline_adjustment_ms);
  return TransactionResult::kOk;
}

RealmTimeController::TransactionResult RealmTimeController::AbortExternalCall(
    uint64_t token, double real_wall_time_ms, uint64_t real_monotonic_time_ns) {
  if (!enabled_) return TransactionResult::kNotEnabled;
  if (!TokenHasCurrentGeneration(token)) {
    return TransactionResult::kStaleGeneration;
  }
  TransactionResult completed = FindCompleted(token, false, 0, 0);
  if (completed != TransactionResult::kNoActiveCall) return completed;
  if (frames_.empty()) return TransactionResult::kNoActiveCall;
  if (frames_.back().token != token) return TransactionResult::kOutOfOrder;
  if (frames_.size() == 1) {
    if (!Resume(0, real_wall_time_ms, real_monotonic_time_ns)) {
      return TransactionResult::kClockOverflow;
    }
  }
  frames_.pop_back();
  RememberCompletion(token, false, 0, 0);
  return TransactionResult::kOk;
}

bool RealmTimeController::Resume(double committed_duration_ms,
                                 double real_wall_time_ms,
                                 uint64_t real_monotonic_time_ns) {
  const double wall_time_offset_ms =
      frozen_wall_time_ms_ + committed_duration_ms - real_wall_time_ms;
  const double monotonic_time_offset_ns =
      frozen_monotonic_time_ns_ +
      committed_duration_ms * kNanosecondsPerMillisecond -
      static_cast<double>(real_monotonic_time_ns);
  if (!std::isfinite(wall_time_offset_ms) ||
      !std::isfinite(monotonic_time_offset_ns) ||
      uv_realm_time_resume(event_loop_, this, committed_duration_ms) != 0) {
    return false;
  }
  if (!ResumeProcessClock(
          this, wall_time_offset_ms, monotonic_time_offset_ns)) {
    return false;
  }
  wall_time_offset_ms_ = wall_time_offset_ms;
  monotonic_time_offset_ns_ = monotonic_time_offset_ns;
  return true;
}

void RealmTimeController::WaitFunctionDuration(
    double function_duration_ms) const {
  if (!std::isfinite(function_duration_ms) || function_duration_ms <= 0) {
    return;
  }
  const long double duration_ns =
      static_cast<long double>(function_duration_ms) * 1'000'000.0L;
  const long double max_duration_ns =
      static_cast<long double>(std::numeric_limits<uint64_t>::max());
  if (duration_ns >= max_duration_ns) return;

  const uint64_t start = uv_hrtime();
  const uint64_t duration = static_cast<uint64_t>(std::ceil(duration_ns));
  if (duration > std::numeric_limits<uint64_t>::max() - start) return;
  const uint64_t target = start + duration;
  while (true) {
    const uint64_t now = uv_hrtime();
    if (now >= target) return;
    const uint64_t remaining = target - now;
    // Let the OS sleep for the coarse part, then yield/spin for the final
    // 0.25ms. This keeps function-duration pacing close to the recording
    // value without allowing JavaScript to re-enter the event loop.
    if (remaining > 250'000) {
      std::this_thread::sleep_for(
          std::chrono::nanoseconds(remaining - 125'000));
    } else {
      std::this_thread::yield();
    }
  }
}

RealmTimeController::TransactionResult RealmTimeController::FindCompleted(
    uint64_t token,
    bool committed,
    double function_duration_ms,
    double timeline_adjustment_ms) const {
  for (auto it = completed_calls_.rbegin(); it != completed_calls_.rend();
       ++it) {
    if (it->token != token) continue;
    if (it->committed == committed &&
        it->function_duration_ms == function_duration_ms &&
        it->timeline_adjustment_ms == timeline_adjustment_ms) {
      return TransactionResult::kIdempotent;
    }
    return TransactionResult::kConflict;
  }
  return TransactionResult::kNoActiveCall;
}

void RealmTimeController::RememberCompletion(uint64_t token,
                                             bool committed,
                                             double function_duration_ms,
                                             double timeline_adjustment_ms) {
  if (completed_calls_.size() == kCompletedCallLimit) {
    completed_calls_.erase(completed_calls_.begin());
  }
  completed_calls_.push_back(
      {token, committed, function_duration_ms, timeline_adjustment_ms});
}

bool RealmTimeController::TokenHasCurrentGeneration(uint64_t token) const {
  return token / kTokenSequenceStride == generation_;
}

const std::string& RealmTimeController::active_operation() const {
  static const std::string empty;
  return frames_.empty() ? empty : frames_.back().operation;
}

double RealmTimeController::CurrentWallTimeMilliseconds(
    double real_wall_time_ms) const {
  return realm_time::CurrentWallTimeMilliseconds(real_wall_time_ms);
}

double CurrentWallTimeMilliseconds(double real_wall_time_ms) {
  ProcessClockSnapshot snapshot = ReadProcessClock();
  if (!snapshot.enabled) return real_wall_time_ms;
  if (snapshot.frozen) return snapshot.frozen_wall_time_ms;
  return real_wall_time_ms + snapshot.wall_time_offset_ms;
}

double RealmTimeController::CurrentMonotonicTimeNanoseconds(
    uint64_t real_monotonic_time_ns) const {
  return realm_time::CurrentMonotonicTimeNanoseconds(real_monotonic_time_ns);
}

double CurrentMonotonicTimeNanoseconds(uint64_t real_monotonic_time_ns) {
  ProcessClockSnapshot snapshot = ReadProcessClock();
  if (!snapshot.enabled) return static_cast<double>(real_monotonic_time_ns);
  if (snapshot.frozen) return snapshot.frozen_monotonic_time_ns;
  return static_cast<double>(real_monotonic_time_ns) +
         snapshot.monotonic_time_offset_ns;
}

int64_t ClampObservableMicroseconds(int64_t microseconds) {
  return ClampToRendererQuantum(microseconds);
}

double ObservableElapsedMilliseconds(double now_ns, double origin_ns) {
  const ClockSurfaceConfig& config = GetClockSurfaceConfig();
  if (config.resolution_ns / 1000 <= 0 || !std::isfinite(now_ns) ||
      !std::isfinite(origin_ns)) {
    return (now_ns - origin_ns) / 1e6;
  }
  // TimeTicks carries microseconds; uv_hrtime carries nanoseconds.
  const int64_t now_us = static_cast<int64_t>(std::floor(now_ns / 1000.0));
  const int64_t origin_us =
      static_cast<int64_t>(std::floor(origin_ns / 1000.0));
  return MicrosecondsToMillisecondsF(ClampToRendererQuantum(now_us)) -
         MicrosecondsToMillisecondsF(ClampToRendererQuantum(origin_us));
}

bool TimerNestingClampEnabled() {
  return ClockSurface().nesting_clamp.load(std::memory_order_relaxed);
}

void InitializeClockSurface() {
  ClockSurface();
}

void TraceClockRead(ClockTraceKind kind,
                    uint64_t real_ns,
                    double value,
                    double aux0,
                    double aux1) {
  ClockTraceState& trace = ClockTrace();
  if (!trace.enabled.load(std::memory_order_relaxed)) return;
  std::lock_guard<std::mutex> lock(trace.mutex);
  if (!trace.enabled.load(std::memory_order_relaxed) || trace.ring.empty()) {
    return;
  }
  ClockTraceRecord& slot = trace.ring[trace.head];
  if (trace.count == trace.ring.size()) {
    trace.dropped++;
  } else {
    trace.count++;
  }
  slot = ClockTraceRecord{trace.next_seq++,
                          real_ns,
                          value,
                          aux0,
                          aux1,
                          static_cast<uint8_t>(kind)};
  trace.head = (trace.head + 1) % trace.ring.size();
  trace.total++;
}

bool ClockTraceEnabled() {
  return ClockTrace().enabled.load(std::memory_order_relaxed);
}

ObservedContext ObservedContextOf(Isolate* isolate) {
  if (isolate == nullptr || !isolate->InContext()) {
    return ObservedContext::kUnknown;
  }
  Local<Context> context = isolate->GetCurrentContext();
  if (context.IsEmpty() || !ContextEmbedderTag::IsNodeContext(context)) {
    return ObservedContext::kUnknown;
  }
  if (Realm::GetCurrent(context) != nullptr) {
    return ObservedContext::kNodeRealm;
  }
  auto* contextify_context = static_cast<contextify::ContextifyContext*>(
      context->GetAlignedPointerFromEmbedderData(
          ContextEmbedderIndex::kContextifyContext,
          EmbedderDataTag::kPerContextData));
  return contextify_context == nullptr ? ObservedContext::kUnknown
                                       : ObservedContext::kVmContext;
}

double PerformanceNowOffsetNanoseconds() {
  return ClockRules().performance_now_offset_ms.load(
             std::memory_order_relaxed) * 1e6;
}

double DateOffsetMilliseconds() {
  return ClockRules().date_offset_ms.load(std::memory_order_relaxed);
}

ClockSurfaceSettings GetClockSurfaceSettings() {
  const ClockSurfaceConfig config = GetClockSurfaceConfig();
  return ClockSurfaceSettings{config.resolution_ns,
                              config.nesting_clamp,
                              uv_realm_timer_grid_get(),
                              config.high_resolution_timer};
}

bool SetClockSurfaceSettings(const ClockSurfaceSettings& settings,
                             std::string* error) {
  if (settings.resolution_ns < 0 ||
      settings.resolution_ns > INT64_C(1000000000000)) {
    *error = "resolutionNs must be in 0..1e12";
    return false;
  }
  if (uv_realm_timer_grid_set(settings.timer_grid_ms) != 0) {
    *error = "timerGridMs must be finite and non-negative";
    return false;
  }
  ClockSurfaceState& state = ClockSurface();
  if (settings.high_resolution_timer !=
      state.high_resolution_timer.load(std::memory_order_relaxed)) {
    if (!ApplyHighResolutionTimer(settings.high_resolution_timer, error)) {
      return false;
    }
    state.high_resolution_timer.store(settings.high_resolution_timer,
                                      std::memory_order_relaxed);
  }
  state.resolution_ns.store(settings.resolution_ns, std::memory_order_relaxed);
  state.nesting_clamp.store(settings.nesting_clamp, std::memory_order_relaxed);
  return true;
}

RealmTimeController* GetController(Local<Context> context) {
  if (context.IsEmpty() || !ContextEmbedderTag::IsNodeContext(context)) {
    return nullptr;
  }
  if (Realm* realm = Realm::GetCurrent(context); realm != nullptr) {
    return realm->realm_time_controller();
  }
  auto* contextify_context = static_cast<contextify::ContextifyContext*>(
      context->GetAlignedPointerFromEmbedderData(
          ContextEmbedderIndex::kContextifyContext,
          EmbedderDataTag::kPerContextData));
  return contextify_context == nullptr
             ? nullptr
             : contextify_context->realm_time_controller();
}

RealmTimeController* GetCurrentController(Isolate* isolate) {
  if (!isolate->InContext()) return nullptr;
  Local<Context> entered_context = isolate->GetEnteredOrMicrotaskContext();
  if (!entered_context.IsEmpty()) {
    if (RealmTimeController* controller = GetController(entered_context)) {
      return controller;
    }
  }
  return GetController(isolate->GetCurrentContext());
}

void InstallTimeSourceCallback(Isolate* isolate) {
  isolate->SetCurrentTimeMillisCallback(RealmDateNowCallback);
}

void UninstallTimeSourceCallback(Isolate* isolate) {
  isolate->SetCurrentTimeMillisCallback(nullptr);
}

void RegisterExternalReferences(ExternalReferenceRegistry* registry) {
  registry->Register(EnableBinding);
  registry->Register(GetClockSurfaceBinding);
  registry->Register(GetReleaseInfoBinding);
  registry->Register(SetFrameBoundaryBinding);
  registry->Register(GetFrameBoundaryBinding);
  registry->Register(SetClockSurfaceBinding);
  registry->Register(StartClockTraceBinding);
  registry->Register(StopClockTraceBinding);
  registry->Register(DrainClockTraceBinding);
  registry->Register(ClockTraceStatsBinding);
  registry->Register(GetClockRulesBinding);
  registry->Register(SetClockRulesBinding);
  registry->Register(DisableBinding);
  registry->Register(IsEnabledBinding);
  registry->Register(BeginExternalCallBinding);
  registry->Register(ParkExternalCallBinding);
  registry->Register(RequestExternalCallBinding);
  registry->Register(CommitExternalCallBinding);
  registry->Register(AbortExternalCallBinding);
  registry->Register(GetStateBinding);
  registry->Register(SetCodeGenerationCallbackBinding);
  registry->Register(SetUncaughtExceptionCallbackBinding);
  registry->Register(GetCodeGenerationRecordsBinding);
  registry->Register(GetExceptionRecordsBinding);
  registry->Register(DisposeDiagnosticsCallback);
  registry->Register(ReplaceSourceControl);
  registry->Register(ReplaceExceptionControl);
}

}  // namespace node::realm_time

NODE_BINDING_CONTEXT_AWARE_INTERNAL(realm_time, node::realm_time::Initialize)
NODE_BINDING_EXTERNAL_REFERENCE(realm_time,
                                node::realm_time::RegisterExternalReferences)
