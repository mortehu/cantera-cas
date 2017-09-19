// Copyright 2013, 2014, 2015, 2016 Morten Hustveit <morten.hustveit@gmail.com>
// Copyright 2013, 2014, 2015, 2016 eVenture Capital Partners
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include "src/progress.h"
#include "src/util.h"

#include <chrono>
#include <cmath>
#include <cstdio>
#include <functional>

#include <unistd.h>

namespace cantera {
namespace cas_internal {

namespace {

std::string SecondsToText(unsigned long long int seconds) {
  if (seconds == 1)
    return "1 second";
  else if (seconds < 2 * 60)
    return StringPrintf("%llu seconds", seconds);
  else if (seconds < 2 * 60 * 60)
    return StringPrintf("%llu:%02llu minutes", seconds / 60, seconds % 60);
  else if (seconds < 2 * 60 * 60 * 24)
    return StringPrintf("%llu:%02llu hours", seconds / 3600,
                        (seconds / 60) % 60);
  else
    return StringPrintf("%llu days and %llu hours", seconds / 86400,
                        (seconds / 3600) % 24);
}

}  // namespace

Progress::Progress(size_t max, std::string description)
    : max_(max),
      description_(std::move(description)),
      start_(Clock::now()),
      paint_thread_(std::bind(&Progress::Paint, this)) {}

Progress::~Progress() {
  {
    std::unique_lock<std::mutex> lk(mutex_);
    done_ = true;
    cv_.notify_all();
  }

  paint_thread_.join();
}

void Progress::Put(size_t n) {
  if (!n) return;

  const auto now = Clock::now();

  std::unique_lock<std::mutex> lk(mutex_);
  value_ = std::min(max_, value_ + n);

  if (!first_put_) {
    put_start_ = now;
    first_put_ = n;
  }

  cv_.notify_all();

  if (value_ == max_) {
    paint_cv_.wait(lk, [this] { return !painting_; });
  }
}

void Progress::Paint() {
  static const auto kMinDrawDelay = std::chrono::milliseconds(100);

  if (1 != isatty(STDERR_FILENO)) {
    painting_ = false;
    paint_cv_.notify_all();
    return;
  }

  fprintf(stderr, "Starting ...\033[K");

  std::unique_lock<std::mutex> lk(mutex_);

  auto last_value = value_;
  TimePoint next_draw = Clock::now();

  while (!done_) {
    bool must_paint = false;

    auto now = Clock::now();
    const std::chrono::duration<double> diff = now - start_;
    const auto next_second =
        now + std::chrono::milliseconds(static_cast<int>(
                  1001 - std::ceil(std::fmod(diff.count(), 1.0) * 1000.0)));

    if (next_draw > next_second) next_draw = next_second;

    // Wait until the counter is updated, or the next second.
    {
      if (!cv_.wait_until(lk, next_second, [this, last_value]() {
            return done_ || value_ != last_value;
          }))
        must_paint = true;
    }

    if (done_ || value_ >= max_) break;

    if (!must_paint && Clock::now() < next_draw) {
      cv_.wait_until(lk, next_draw, [this]() { return done_; });
    }

    const auto percentage = 100.0 * value_ / max_;

    now = Clock::now();
    std::chrono::duration<double> duration = now - start_;

    std::string status = StringPrintf(
        "%zu / %zu %s.  %.1f%% in %s.", value_, max_, description_.c_str(),
        percentage, SecondsToText(std::floor(duration.count())).c_str());

    if (value_ > 10 * first_put_) {
      std::chrono::duration<double> put_duration = now - put_start_;
      const auto interval = put_duration.count() / (value_ - first_put_);

      status += StringPrintf(
          "  %s remaining.",
          SecondsToText(std::round((max_ - value_) * interval)).c_str());
    }

    fprintf(stderr, "\r%s\033[K", status.c_str());

    last_value = value_;

    next_draw = now + kMinDrawDelay;
  }

  fprintf(
      stderr, "\rDone: %zu %s, %.1f / second\033[K\n", value_,
      description_.c_str(),
      value_ / std::chrono::duration<double>(Clock::now() - start_).count());

  painting_ = false;
  paint_cv_.notify_all();
}

}  // namespace cas_internal
}  // namespace cantera
