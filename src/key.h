#ifndef CANTERA_CAS_KEY_H_
#define CANTERA_CAS_KEY_H_ 1

#include <array>
#include <experimental/string_view>

#include <capnp/common.h>
#include <kj/array.h>

namespace cantera {

using string_view = std::experimental::string_view;

struct CASKey : public std::array<uint8_t, 20> {
  // Converts a key string into its binary representation.
  static CASKey FromString(const string_view& hex);

  CASKey() noexcept;

  CASKey(const kj::ArrayPtr<const capnp::byte>& key) noexcept;

  CASKey(const uint8_t* key) noexcept;

  CASKey(const CASKey& rhs) noexcept;

  CASKey(CASKey&& rhs) noexcept;

  ~CASKey();

  CASKey& operator=(const CASKey& rhs) noexcept;

  CASKey& operator=(CASKey&& rhs) noexcept;

  // Returns a 64 byte integer based on the key prefix.
  uint64_t Prefix() const;

  // Returns a 64 byte integer based on the key suffix.
  uint64_t Suffix() const;

  // Converts binary key into a 40 character hexadecimal string.
  std::string ToHex() const;
};

}  // namespace cantera

namespace std {

template <>
struct hash<cantera::CASKey> {
  typedef cantera::CASKey argument_type;
  typedef std::size_t result_type;

  // Returns a hash based on a CAS key.  Since the input is already a hash, we
  // need to do some minimal mixing to avoid clustering when the inputs are
  // selected from a small number of segments in a consistent hash ring.
  result_type operator()(argument_type const& key) const {
    result_type result(0);
    for (unsigned int i = 0; i < 20; ++i)
      result ^= static_cast<result_type>(key[i]) << ((i & 7) * 8);
    return result;
  }
};

}  // namespace std

#endif  // !STORAGE_CA_CAS_KEY_H_
