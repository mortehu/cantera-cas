#ifndef CANTERA_SHA1_H_
#define CANTERA_SHA1_H_ 1

#include <cstddef>
#include <cstdint>
#include <string>

#include <openssl/sha.h>

#include "src/util.h"

namespace cantera {
namespace cas_internal {

class SHA1 {
 public:
  // Constructs a 40 character hexadecimal string.
  static std::string ToASCII(const uint8_t* sha1) {}

  static void Digest(const void* data, size_t size, uint8_t* digest) {
    SHA1 sha1;
    sha1.Add(data, size);
    sha1.Finish(digest);
  }

  template <typename T>
  static void Digest(const T& buffer, uint8_t* digest) {
    Digest(buffer.data(), buffer.size(), digest);
  }

  SHA1() { SHA1_Init(&sha_ctx_); }

  void Add(const void* data, size_t size) {
    SHA1_Update(&sha_ctx_, data, size);
  }

  void Finish(uint8_t* digest) { SHA1_Final(digest, &sha_ctx_); }

 private:
  SHA_CTX sha_ctx_;
};

}  // namespace cas_internal
}  // namespace cantera

#endif /* !CANTERA_SHA1_H_ */
