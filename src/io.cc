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

#include "src/io.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include <cstring>
#include <memory>
#include <random>

#include <kj/debug.h>

#include "src/util.h"

namespace cantera {
namespace cas_internal {

namespace {

// Disposes an array by calling the C library function "free".
class FreeArrayDisposer : public kj::ArrayDisposer {
 public:
  static const FreeArrayDisposer instance;

  FreeArrayDisposer() {}

  void disposeImpl(void* firstElement, size_t elementSize, size_t elementCount,
                   size_t capacity,
                   void (*destroyElement)(void*)) const override {
    KJ_REQUIRE(destroyElement == nullptr, destroyElement);
    std::free(firstElement);
  }
};

// Disposes an array by calling munmap.
class MunmapArrayDisposer : public kj::ArrayDisposer {
 public:
  static const MunmapArrayDisposer instance;

  MunmapArrayDisposer() {}

  void disposeImpl(void* firstElement, size_t elementSize, size_t elementCount,
                   size_t capacity,
                   void (*destroyElement)(void*)) const override {
    KJ_REQUIRE(destroyElement == nullptr, destroyElement);
    KJ_SYSCALL(munmap(firstElement, elementSize * elementCount));
  }
};

const FreeArrayDisposer FreeArrayDisposer::instance;
const MunmapArrayDisposer MunmapArrayDisposer::instance;

void MakeRandomString(char* output, size_t length) {
  static uint64_t counter = CurrentTimeUSec();
  std::minstd_rand rng;
  rng.seed(++counter);

  static const char kLetters[] =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

  std::uniform_int_distribution<uint8_t> rng_dist(0, strlen(kLetters) - 1);

  while (length--) *output++ = kLetters[rng_dist(rng)];
}

}  // namespace

kj::AutoCloseFd OpenFile(const char* path, int flags, int mode) {
  int fd;
  KJ_SYSCALL(fd = open(path, flags, mode), path);
  return kj::AutoCloseFd(fd);
}

// Opens a file relative to the directory given by `dir_fd`, throwing an
// exception if the operation fails for any reason.
kj::AutoCloseFd OpenFile(int dir_fd, const char* path, int flags, int mode) {
  int fd;
  KJ_SYSCALL(fd = openat(dir_fd, path, flags, mode), path);
  return kj::AutoCloseFd(fd);
}

kj::Array<const char> ReadFile(int fd) {
  static const size_t kMinBufferSize = 1024 * 1024;

  off_t size = lseek(fd, 0, SEEK_END);
  if (size == -1) {
    if (errno != ESPIPE) {
      KJ_SYSCALL("lseek", errno);
    }

    // Unseekable file descriptor; let's just read into a vector.

    std::unique_ptr<char[], decltype(&std::free)> buffer(nullptr, std::free);
    size_t size = 0, alloc = 0;
    for (;;) {
      if (size == alloc) {
        alloc = size + kMinBufferSize;
        auto old_buffer = buffer.release();
        std::unique_ptr<char[], decltype(&std::free)> new_buffer(
            reinterpret_cast<char*>(realloc(old_buffer, alloc)), std::free);
        if (!new_buffer) {
          free(old_buffer);
          KJ_FAIL_SYSCALL("realloc", errno, alloc);
        }
        buffer = std::move(new_buffer);
      }

      size_t read_amount = alloc - size;
      ssize_t ret = ::read(fd, &buffer.get()[size], read_amount);
      if (ret < 0) KJ_FAIL_SYSCALL("read", errno);
      if (ret == 0) break;
      size += ret;
    }

    return kj::Array<const char>(buffer.release(), size,
                                 FreeArrayDisposer::instance);
  } else if (size == 0) {
    return kj::Array<const char>();
  } else {
    void* map = mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) KJ_FAIL_SYSCALL("mmap", errno);

    return kj::Array<const char>(reinterpret_cast<const char*>(map), size,
                                 MunmapArrayDisposer::instance);
  }
}

size_t ReadWithOffset(int fd, void* dest, size_t size_min, size_t size_max,
                      off_t offset) {
  size_t result = 0;

  while (size_max > 0) {
    ssize_t ret;
    KJ_SYSCALL(ret = pread(fd, dest, size_max, offset));
    if (ret == 0) break;
    result += ret;
    size_max -= ret;
    offset += ret;
    dest = reinterpret_cast<char*>(dest) + ret;
  }

  KJ_REQUIRE(result >= size_min, "unexpectedly reached end of file", offset,
             result, size_min);

  return result;
}

kj::AutoCloseFd AnonTemporaryFile(const char* path, int mode) {
  if (!path) {
    path = getenv("TMPDIR");
    if (!path) path = "/tmp";
  }

#ifdef O_TMPFILE
  return OpenFile(path, O_TMPFILE | O_RDWR, mode);
#else
  size_t pathlen = std::strlen(path);
  static const char suffix[] = "/ca-cas-XXXXXX";
  std::unique_ptr<char[]> pathname(new char[pathlen + sizeof(suffix)]);
  std::memcpy((void *)(pathname.get()), path, pathlen);
  std::memcpy((void *)(pathname.get() + pathlen), suffix, sizeof(suffix));

  int fd;
  KJ_SYSCALL(fd = ::mkstemp(pathname.get()), pathname.get());
  KJ_SYSCALL(unlink(pathname.get()), pathname.get());
  return kj::AutoCloseFd(fd);
#endif
}

void LinkAnonTemporaryFile(int dir_fd, int fd, const char* path) {
  KJ_CONTEXT(path);
  char temp_path[32];
  snprintf(temp_path, sizeof(temp_path), "/proc/self/fd/%d", fd);
  auto ret = linkat(AT_FDCWD, temp_path, dir_fd, path, AT_SYMLINK_FOLLOW);
  if (ret == 0) return;
  if (errno != EEXIST) {
    const auto linkat_errno = errno;
    KJ_SYSCALL(access("/proc", X_OK), "/proc is not available");
    KJ_FAIL_SYSCALL("linkat", linkat_errno, temp_path);
  }

  // Target already exists, so we need an intermediate filename to atomically
  // replace with rename().
  std::string intermediate_path = path;
  intermediate_path += ".XXXXXX";

  static const size_t kMaxAttempts = 62 * 62 * 62;

  for (size_t i = 0; i < kMaxAttempts; ++i) {
    MakeRandomString(&intermediate_path[intermediate_path.size() - 6], 6);

    ret = linkat(AT_FDCWD, temp_path, dir_fd, intermediate_path.c_str(),
                 AT_SYMLINK_FOLLOW);

    if (ret == 0) {
      KJ_SYSCALL(renameat(dir_fd, intermediate_path.c_str(), dir_fd, path),
                 intermediate_path, path);
      return;
    }

    if (errno != EEXIST) {
      KJ_FAIL_SYSCALL("linkat", errno, intermediate_path, path);
    }
  }

  KJ_FAIL_REQUIRE("all temporary file creation attempts failed", kMaxAttempts);
}

}  // namespace cas_internal
}  // namespace ev
