#include "node_realm_time.h"

#include "env-inl.h"
#include "node_binding.h"
#include "node_context_data.h"
#include "node_contextify.h"
#include "node_external_reference.h"
#include "node_internals.h"
#include "node_realm-inl.h"
#include "util-inl.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cmath>
#include <cstdlib>
#include <limits>
#include <string_view>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace node::realm_time {

using v8::Boolean;
using v8::Context;
using v8::FunctionCallbackInfo;
using v8::HandleScope;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::Null;
using v8::Number;
using v8::Object;
using v8::String;
using v8::Value;

namespace {

constexpr double kNanosecondsPerMillisecond = 1e6;
constexpr uint64_t kMaxSafeInteger = 9007199254740991ULL;
constexpr uint64_t kTokenSequenceStride = 1ULL << 24;
constexpr size_t kCompletedCallLimit = 256;
constexpr size_t kMaxControllerResponseBytes = 64 * 1024 * 1024;

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

double RealWallTimeMilliseconds(Environment* env) {
  return std::floor(env->isolate_data()->platform()->CurrentClockTimeMillis());
}

uint64_t RealMonotonicTimeNanoseconds() {
  return uv_hrtime();
}

int64_t RealmDateNowCallback(Isolate* isolate, int64_t real_time_millis) {
  HandleScope handle_scope(isolate);
  RealmTimeController* controller = GetCurrentController(isolate);
  if (controller == nullptr) return real_time_millis;

  double result = controller->CurrentWallTimeMilliseconds(real_time_millis);
  if (!std::isfinite(result) ||
      result < static_cast<double>(std::numeric_limits<int64_t>::min()) ||
      result > static_cast<double>(std::numeric_limits<int64_t>::max())) {
    return real_time_millis;
  }
  return static_cast<int64_t>(std::floor(result));
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
  if (!args[2]->IsUint32()) {
    env->ThrowTypeError("port must be an unsigned integer");
    return;
  }
  uint32_t port = args[2].As<Integer>()->Value();
  if (port == 0 || port > 65535) {
    env->ThrowRangeError("port must be between 1 and 65535");
    return;
  }
  if (!args[3]->IsString() || !args[4]->IsString()) {
    env->ThrowTypeError("path and body must be strings");
    return;
  }
  Utf8Value path_value(env->isolate(), args[3]);
  Utf8Value body_value(env->isolate(), args[4]);
  if (*path_value == nullptr || path_value.length() == 0 ||
      (*path_value)[0] != '/' ||
      std::string_view(*path_value, path_value.length())
              .find_first_of("\r\n") != std::string_view::npos) {
    env->ThrowRangeError("path must be an absolute HTTP path without newlines");
    return;
  }
  if (*body_value == nullptr) {
    env->ThrowError("failed to encode request body as UTF-8");
    return;
  }
  std::string path(*path_value, path_value.length());
  std::string body(*body_value, body_value.length());

  if (!ReturnTransactionResult(env, controller->ParkExternalCall(token))) {
    return;
  }

  NativeSocket socket_handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (socket_handle == kInvalidSocket) {
    env->ThrowError("failed to create Controller socket");
    return;
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
    return;
  }

  std::string request;
  request.reserve(body.size() + path.size() + 256);
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
      .append(std::to_string(controller->generation()))
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
    return;
  }

  std::string response;
  char buffer[16 * 1024];
  while (true) {
    int received = recv(socket_handle, buffer, sizeof(buffer), 0);
    if (received == 0) break;
    if (received < 0) {
      CloseNativeSocket(socket_handle);
      env->ThrowError("failed to receive the Controller response");
      return;
    }
    if (response.size() > kMaxControllerResponseBytes + 64 * 1024 - received) {
      CloseNativeSocket(socket_handle);
      env->ThrowRangeError("Controller response exceeds the 64 MiB limit");
      return;
    }
    response.append(buffer, static_cast<size_t>(received));
  }
  CloseNativeSocket(socket_handle);

  int status_code;
  std::string response_body;
  if (!ParseHttpResponse(response, &status_code, &response_body)) {
    env->ThrowError("Controller returned an invalid HTTP response");
    return;
  }

  Isolate* isolate = args.GetIsolate();
  Local<Context> context = isolate->GetCurrentContext();
  Local<Object> result = Object::New(isolate);
  result
      ->Set(context,
            OneByteString(isolate, "statusCode"),
            Integer::New(isolate, status_code))
      .Check();
  Local<String> response_body_value;
  if (!String::NewFromUtf8(isolate,
                           response_body.data(),
                           v8::NewStringType::kNormal,
                           static_cast<int>(response_body.size()))
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
}

}  // namespace

bool RealmTimeController::Enable(double real_wall_time_ms,
                                 uint64_t real_monotonic_time_ns,
                                 uv_loop_t* event_loop) {
  if (event_loop == nullptr) return false;
  if (enabled_) uv_realm_time_disable(event_loop_, this);
  if (uv_realm_time_enable(event_loop, this) != 0) return false;

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
    if (uv_realm_time_freeze(event_loop_, this) != 0) return kInvalidToken;
  }
  uint64_t token = NextToken();
  if (token == kInvalidToken) {
    if (frames_.empty()) uv_realm_time_resume(event_loop_, this, 0);
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
  if (frames_.size() > 1) {
    double parent_duration = frames_[frames_.size() - 2].committed_duration_ms +
                             committed_duration_ms;
    if (!std::isfinite(parent_duration)) {
      return TransactionResult::kClockOverflow;
    }
    frames_[frames_.size() - 2].committed_duration_ms = parent_duration;
  } else if (!Resume(committed_duration_ms,
                     real_wall_time_ms,
                     real_monotonic_time_ns)) {
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
  if (frames_.size() == 1 &&
      !Resume(0, real_wall_time_ms, real_monotonic_time_ns)) {
    return TransactionResult::kClockOverflow;
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
  wall_time_offset_ms_ = wall_time_offset_ms;
  monotonic_time_offset_ns_ = monotonic_time_offset_ns;
  return true;
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
  if (!enabled_) return real_wall_time_ms;
  if (frozen()) return frozen_wall_time_ms_;
  return real_wall_time_ms + wall_time_offset_ms_;
}

double RealmTimeController::CurrentMonotonicTimeNanoseconds(
    uint64_t real_monotonic_time_ns) const {
  if (!enabled_) return static_cast<double>(real_monotonic_time_ns);
  if (frozen()) return frozen_monotonic_time_ns_;
  return static_cast<double>(real_monotonic_time_ns) +
         monotonic_time_offset_ns_;
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
  registry->Register(DisableBinding);
  registry->Register(IsEnabledBinding);
  registry->Register(BeginExternalCallBinding);
  registry->Register(ParkExternalCallBinding);
  registry->Register(RequestExternalCallBinding);
  registry->Register(CommitExternalCallBinding);
  registry->Register(AbortExternalCallBinding);
  registry->Register(GetStateBinding);
}

}  // namespace node::realm_time

NODE_BINDING_CONTEXT_AWARE_INTERNAL(realm_time, node::realm_time::Initialize)
NODE_BINDING_EXTERNAL_REFERENCE(realm_time,
                                node::realm_time::RegisterExternalReferences)
