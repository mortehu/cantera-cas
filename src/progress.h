#ifndef CANTERAPROGRESS_H_
#define CANTERAPROGRESS_H_

#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace cantera {
namespace cas_internal {

// Draws a progress indicator if standard error is a TTY.
class Progress {
 public:
  Progress(size_t max, std::string description);

  ~Progress();

  void Put(size_t n);

 private:
  using Clock = std::chrono::steady_clock;

  typedef std::chrono::time_point<Clock> TimePoint;

  // Number of timing samples to keep track of in `timings_`.
  static const size_t kReservoirSize = 10000;

  void Paint();

  size_t max_;

  std::string description_;

  TimePoint start_;

  std::mutex mutex_;
  std::condition_variable cv_;

  // Set to `true` to stop the paint thread.
  bool done_ = false;

  // Set to `false` when the paint thread is no longer running.
  std::condition_variable paint_cv_;
  bool painting_ = true;

  size_t value_ = 0;

  // Keep thread at end of class to make sure everything else get inited first.
  std::thread paint_thread_;

  TimePoint put_start_;
  size_t first_put_ = 0;
};

}  // namespace cas_internal
}  // namespace ev

#endif  // !CANTERA_PROGRESS_H_
