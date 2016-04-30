#ifndef CANTERA_UTIL_H_
#define CANTERA_UTIL_H_ 1

#include <cctype>
#include <cinttypes>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <string>

#include <sys/time.h>

#include <kj/debug.h>

namespace cantera {
namespace cas_internal {

extern const char kBase64Chars[];
extern const char kBase64WebSafeChars[];

template <typename T>
void BinaryToHex(const void* input, size_t size, T* output) {
  const auto u8input = reinterpret_cast<const uint8_t*>(input);

  static const char kHexDigits[] = "0123456789abcdef";

  for (size_t i = 0; i < size; ++i) {
    output->push_back(kHexDigits[u8input[i] >> 4]);
    output->push_back(kHexDigits[u8input[i] & 15]);
  }
}

template <typename InputIterator, typename OutputIterator>
void HexToBinary(InputIterator begin, InputIterator end,
                 OutputIterator output) {
  // This LUT takes advantage of the fact that the lower 5 bits in the ASCII
  // representation of all hexadecimal digits are unique.
  static const uint8_t kHexHelper[26] = {0, 10, 11, 12, 13, 14, 15, 0, 0,
                                         0, 0,  0,  0,  0,  0,  0,  0, 1,
                                         2, 3,  4,  5,  6,  7,  8,  9};

  while (begin != end) {
    auto c0 = *begin++;
    if (begin == end)
      KJ_FAIL_REQUIRE("hexadecimal number has odd number of digits");
    auto c1 = *begin++;

    if (!std::isxdigit(c0) || !std::isxdigit(c1))
      KJ_FAIL_REQUIRE("input is not hexadecimal");

    *output++ = (kHexHelper[c0 & 0x1f] << 4) | (kHexHelper[c1 & 0x1f]);
  }
}

inline uint64_t StringToUInt64(const char* string) {
  static_assert(std::is_same<unsigned long, uint64_t>::value, "");
  KJ_REQUIRE(*string != 0);
  char* endptr = nullptr;
  errno = 0;
  const auto value = std::strtoul(string, &endptr, 0);
  KJ_REQUIRE(*endptr == 0, "unexpected character in numeric string", string);
  if (errno != 0) {
    KJ_FAIL_SYSCALL("strtoul", errno, string);
  }
  return value;
}

// Returns the current time in microseconds.
inline uint64_t CurrentTimeUSec() {
  struct timeval now;
  gettimeofday(&now, nullptr);
  return now.tv_sec * UINT64_C(1000000) + now.tv_usec;
}

template <typename T>
unsigned char* Base64ToBinary(const T& input, unsigned char* output) {
  static const unsigned char kBase64DecodeMap[] = {
      0x3e, 0xff, 0xff, 0xff, 0x3f, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a,
      0x3b, 0x3c, 0x3d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x01,
      0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
      0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
      0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
      0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33};

  unsigned int v = 0, o = 0;

  for (auto i = input.begin(); i != input.end() && *i != '='; ++i) {
    if (std::isspace(*i)) continue;

    const auto index = *i - 43;

    KJ_REQUIRE(index < sizeof(kBase64DecodeMap) / sizeof(kBase64DecodeMap[0]));
    KJ_REQUIRE(kBase64DecodeMap[index] != 0xff);

    v = (v << 6) + kBase64DecodeMap[index];

    if (o & 3) *output++ = v >> (6 - 2 * (o & 3));
    ++o;
  }

  return output;
}

template <typename T>
void ToBase64(const T& input, std::string& output, const char* alphabet) {
  if (input.empty()) return;

  const auto orig_output_size = output.size();
  output.reserve(output.size() + input.size() * 4 / 3 + 12);

  auto in = reinterpret_cast<const uint8_t*>(input.data());
  auto remaining = input.size();
  unsigned int i_bits = 0;
  int i_shift = 0;

  while (remaining) {
    // Consume one byte.
    i_bits = (i_bits << 8) + *in++;
    --remaining;
    i_shift += 8;

    // Output 6 bits at a time.  Keep going if last input byte has been
    // consumed.
    do {
      output.push_back(alphabet[(i_bits << 6 >> i_shift) & 0x3f]);
      i_shift -= 6;
    } while (i_shift > 6 || (!remaining && i_shift > 0));
  }

  // Apply padding needed by some decoders.
  while ((output.size() - orig_output_size) & 3) output.push_back('=');
}

inline std::string StringPrintf(const char* format, ...) {
  va_list args;
  char* buf;

  va_start(args, format);

  KJ_SYSCALL(vasprintf(&buf, format, args));

  std::string result(buf);
  std::free(buf);

  return result;
}

}  // namespace cas_internal
}  // namespace cantera

#endif  // !CANTERA_UTIL_H_
