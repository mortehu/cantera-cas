#ifndef CANTERA_IO_H_
#define CANTERA_IO_H_ 1

#include <algorithm>
#include <vector>

#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include <kj/debug.h>
#include <kj/io.h>

namespace cantera {
namespace cas_internal {

// Opens a file, throwing an exception if the operation fails for any reason.
kj::AutoCloseFd OpenFile(const char* path, int flags, int mode = 0666);

// Opens a file relative to the directory given by `dir_fd`, throwing an
// exception if the operation fails for any reason.
kj::AutoCloseFd OpenFile(int dir_fd, const char* path, int flags,
                         int mode = 0666);

kj::Array<const char> ReadFile(int fd);

size_t ReadWithOffset(int fd, void* dest, size_t size_min, size_t size_max,
                      off_t offset);

inline void ReadWithOffset(int fd, void* dest, size_t size, off_t offset) {
  ReadWithOffset(fd, dest, size, size, offset);
}

kj::AutoCloseFd AnonTemporaryFile(const char* path, int mode = 0666);

void LinkAnonTemporaryFile(int dir_fd, int fd, const char* path);

inline void LinkAnonTemporaryFile(int fd, const char* path) {
  LinkAnonTemporaryFile(AT_FDCWD, fd, path);
}

template <typename StringType, typename T>
void ReadLines(int fd, T&& callback) {
  std::vector<char> buffer;

  for (;;) {
    const auto read_offset = buffer.size();
    buffer.resize(buffer.size() + 65536);

    ssize_t ret;
    KJ_SYSCALL(
        ret = ::read(fd, &buffer[read_offset], buffer.size() - read_offset));
    if (!ret) break;

    // "Vector capacity is never reduced when resizing to smaller size [...]"
    buffer.resize(read_offset + ret);

    auto consumed = buffer.begin();

    do {
      const auto line_end = std::find(consumed, buffer.end(), '\n');

      if (line_end == buffer.end()) break;

      callback(
          StringType{&*consumed, static_cast<size_t>(line_end - consumed)});

      consumed = line_end + 1;
    } while (consumed != buffer.end());

    buffer.erase(buffer.begin(), consumed);
  }
}

}  // namespace cas_internal
}  // namespace ev

#endif  // !CANTERA_IO_H_
