// Content addressable storage integrity checker
//
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cassert>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <future>
#include <mutex>

#include <err.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sysexits.h>
#include <unistd.h>

#include <kj/debug.h>

#include "src/io.h"
#include "src/sha1.h"
#include "src/storage-server.h"
#include "src/util.h"

using namespace cantera;

namespace {

// Extracts a random sample of length `n` from the range `first`..`last`,
// writing the result to output iterator `out`.
template <typename ForwardIterator, typename OutputIterator, typename Distance,
          typename RNG>
OutputIterator RandomSample(ForwardIterator first, ForwardIterator last,
                            OutputIterator out, const Distance n, RNG&& rng) {
  Distance remaining = std::distance(first, last);
  Distance m = std::min(n, remaining);

  while (m > 0) {
    std::uniform_int_distribution<size_t> rng_dist(0, remaining - 1);

    if (rng_dist(rng) < m) {
      *out++ = *first;
      --m;
    }

    --remaining;
    ++first;
  }

  return out;
}

const auto kBucketMask = UINT64_C(0x3f00000000000000);
const auto kDeletedMask = UINT64_C(0x8000000000000000);
const auto kOffsetMask = UINT64_C(0x00ffffffffffffff);

// Number of objects to verify in each CAS repository.  The objects are
// randomly selected, so that repeated runs improve the coverage.  By making
// this an absolute number rather than a fraction, the running time of a check
// remains predictable.
size_t num_sha1_verify = 10000;

int print_version;
int print_help;

// Some of our code uses a lot of memory temporarily.  This mutex prevents
// multiple instances of that code from running in parallel.
std::mutex big_memory;

struct option long_options[] = {{"version", no_argument, &print_version, 1},
                                {"help", no_argument, &print_help, 1},
                                {0, 0, 0, 0}};

std::exception_ptr CheckRepository(std::string path) {
  try {
    KJ_CONTEXT(path);

    auto dir_fd = cas_internal::OpenFile(path.c_str(), O_RDONLY | O_DIRECTORY);
    auto index_fd = cas_internal::OpenFile(dir_fd.get(), "index", O_RDONLY);

    off_t index_size;
    KJ_SYSCALL(index_size = lseek(index_fd.get(), 0, SEEK_END));

    if (!index_size) return nullptr;

    std::vector<kj::AutoCloseFd> data_fds;
    std::vector<uint64_t> data_sizes;

    for (size_t i = 0; i < 50; ++i) {
      std::string filename("data");
      if (i > 0) filename += cas_internal::StringPrintf(".%02zu", i);
      data_fds.emplace_back(
          cas_internal::OpenFile(dir_fd.get(), filename.c_str(), O_RDONLY));

      off_t data_size;
      KJ_SYSCALL(data_size = lseek(data_fds.back().get(), 0, SEEK_END));
      data_sizes.emplace_back(data_size);
    }

    std::unique_lock<std::mutex> memory_lock(big_memory);

    std::vector<StorageServer::IndexEntry> index;
    index.resize(index_size / sizeof(StorageServer::IndexEntry));

    cas_internal::ReadWithOffset(
        index_fd.get(), index.data(),
        index.size() * sizeof(StorageServer::IndexEntry), 0);

    // Remove duplicate entries in index, keeping the last instance.
    std::stable_sort(
        index.begin(), index.end(),
        [](const auto& lhs, const auto& rhs) { return lhs.key < rhs.key; });
    auto new_begin = std::unique(
        index.rbegin(), index.rend(),
        [](const auto& lhs, const auto& rhs) { return lhs.key == rhs.key; });
    index.erase(index.begin(), new_begin.base());

    // Remove deleted objects.
    index.erase(
        std::remove_if(index.begin(), index.end(),
                       [](const auto& v) { return (v.offset & kDeletedMask); }),
        index.end());

    if (index.size() > num_sha1_verify) {
      std::mt19937_64 strong_rng{std::random_device{}()};

      index.erase(RandomSample(index.begin(), index.end(), index.begin(),
                               num_sha1_verify, strong_rng),
                  index.end());
    }

    index.shrink_to_fit();
    memory_lock.unlock();

    // Order index entries by offset in order to minimize seeks.
    std::sort(index.begin(), index.end(), [](const auto& lhs, const auto& rhs) {
      return lhs.offset < rhs.offset;
    });

    std::vector<char> buffer;

    for (auto i = index.begin(); i != index.end(); ++i) {
      if (i->offset & kDeletedMask) continue;

      const auto offset = i->offset & kOffsetMask;
      const auto data_file_idx = (i->offset & kBucketMask) >> 56;

      KJ_REQUIRE(offset + i->size <= data_sizes[data_file_idx]);

      buffer.resize(i->size);

      cas_internal::ReadWithOffset(data_fds[data_file_idx].get(), buffer.data(),
                                   i->size, offset);

      std::array<uint8_t, 20> digest;
      cas_internal::SHA1::Digest(buffer, digest.begin());

      KJ_REQUIRE(std::equal(digest.begin(), digest.end(), i->key.begin(),
                            i->key.end()));
    }
  } catch (...) {
    return std::current_exception();
  }

  return nullptr;
}

}  // namespace

int main(int argc, char** argv) try {
  int i;

  while ((i = getopt_long(argc, argv, "", long_options, 0)) != -1) {
    switch (i) {
      case 0:

        break;

      case '?':

        errx(EX_USAGE, "Try '%s --help' for more information.", argv[0]);
    }
  }

  if (print_help) {
    printf(
        "Usage: %s [OPTION]... CAS-ROOT...\n"
        "\n"
        "      --help     display this help and exit\n"
        "      --version  display version information and exit\n"
        "\n"
        "Report bugs to <morten.hustveit@gmail.com>\n",
        argv[0]);

    return EXIT_SUCCESS;
  }

  if (print_version) {
    fprintf(stdout, "%s\n", PACKAGE_STRING);

    return EXIT_SUCCESS;
  }

  if (optind + 1 > argc) errx(EX_USAGE, "Usage: %s [OPTION]... ROOT", argv[0]);

  std::deque<std::future<std::exception_ptr>> threads;

  while (optind < argc) {
    while (threads.size() > std::thread::hardware_concurrency()) {
      auto exception = threads.front().get();
      threads.pop_front();
      if (exception) std::rethrow_exception(exception);
    }

    std::string path = argv[optind++];

    threads.emplace_back(std::async(
        std::launch::async,
        [path = std::move(path)] { return CheckRepository(std::move(path)); }));
  }

  while (!threads.empty()) {
    auto exception = threads.front().get();
    threads.pop_front();
    if (exception) std::rethrow_exception(exception);
  }
} catch (kj::Exception e) {
  KJ_LOG(FATAL, e);
  _Exit(EXIT_FAILURE);
}
