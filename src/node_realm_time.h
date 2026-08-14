#ifndef SRC_NODE_REALM_TIME_H_
#define SRC_NODE_REALM_TIME_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include <uv.h>
#include <v8.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace node {

class ExternalReferenceRegistry;

namespace realm_time {

class RealmTimeController final {
 public:
  static constexpr uint64_t kInvalidToken = 0;

  enum class TransactionResult {
    kOk,
    kIdempotent,
    kNotEnabled,
    kNoActiveCall,
    kOutOfOrder,
    kStaleGeneration,
    kConflict,
    kInvalidDuration,
    kClockOverflow,
    kNotParked,
    kNotCompleted,
  };

  bool Enable(double real_wall_time_ms,
              uint64_t real_monotonic_time_ns,
              uv_loop_t* event_loop);
  void Disable();

  uint64_t BeginExternalCall(double real_wall_time_ms,
                             uint64_t real_monotonic_time_ns,
                             std::string operation);
  TransactionResult ParkExternalCall(uint64_t token);
  TransactionResult CommitExternalCall(uint64_t token,
                                       double function_duration_ms,
                                       double timeline_adjustment_ms,
                                       double real_wall_time_ms,
                                       uint64_t real_monotonic_time_ns);
  TransactionResult AbortExternalCall(uint64_t token,
                                       double real_wall_time_ms,
                                       uint64_t real_monotonic_time_ns);
  TransactionResult ValidateReleaseExternalCall(uint64_t token) const;

  double CurrentWallTimeMilliseconds(double real_wall_time_ms) const;
  double CurrentMonotonicTimeNanoseconds(uint64_t real_monotonic_time_ns) const;

  bool enabled() const { return enabled_; }
  bool frozen() const { return !frames_.empty(); }
  size_t depth() const { return frames_.size(); }
  uint64_t generation() const { return generation_; }
  bool parked() const { return !frames_.empty() && frames_.back().parked; }
  const std::string& active_operation() const;
  uint64_t active_token() const {
    return frames_.empty() ? kInvalidToken : frames_.back().token;
  }

 private:
  struct ExternalCallFrame {
    uint64_t token;
    std::string operation;
    bool parked = false;
    double committed_duration_ms = 0;
  };

  struct CompletedCall {
    uint64_t token;
    bool committed;
    double function_duration_ms;
    double timeline_adjustment_ms;
  };

  bool Resume(double committed_duration_ms,
              double real_wall_time_ms,
              uint64_t real_monotonic_time_ns);
  TransactionResult FindCompleted(uint64_t token,
                                  bool committed,
                                  double function_duration_ms,
                                  double timeline_adjustment_ms) const;
  void RememberCompletion(uint64_t token,
                          bool committed,
                          double function_duration_ms,
                          double timeline_adjustment_ms);
  bool TokenHasCurrentGeneration(uint64_t token) const;
  uint64_t NextToken();

  bool enabled_ = false;
  uint64_t generation_ = 0;
  uint64_t next_sequence_ = 0;
  uv_loop_t* event_loop_ = nullptr;
  double wall_time_offset_ms_ = 0;
  double monotonic_time_offset_ns_ = 0;
  double frozen_wall_time_ms_ = 0;
  double frozen_monotonic_time_ns_ = 0;
  std::vector<ExternalCallFrame> frames_;
  std::vector<CompletedCall> completed_calls_;
};

RealmTimeController* GetController(v8::Local<v8::Context> context);
RealmTimeController* GetCurrentController(v8::Isolate* isolate);

void InstallTimeSourceCallback(v8::Isolate* isolate);
void UninstallTimeSourceCallback(v8::Isolate* isolate);
void RegisterExternalReferences(ExternalReferenceRegistry* registry);

}  // namespace realm_time
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_NODE_REALM_TIME_H_
