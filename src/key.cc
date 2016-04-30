#include "key.h"

#include <kj/debug.h>

#include "util.h"

namespace cantera {

CASKey CASKey::FromString(const string_view& hex) {
  KJ_REQUIRE(hex.size() == 40, hex.size());
  CASKey result;
  cas_internal::HexToBinary(hex.begin(), hex.end(), result.begin());
  return result;
}

CASKey::CASKey() noexcept {}

CASKey::CASKey(const kj::ArrayPtr<const capnp::byte>& key) noexcept {
  KJ_REQUIRE(key.size() == 20, key.size());
  std::copy(key.begin(), key.end(), begin());
}

CASKey::CASKey(const uint8_t* key) noexcept { std::copy(key, key + 20, begin()); }

CASKey::CASKey(const CASKey& rhs) noexcept : std::array<uint8_t, 20>(rhs) {}

CASKey::CASKey(CASKey&& rhs) noexcept : std::array<uint8_t, 20>(rhs) {}

CASKey::~CASKey() {}

CASKey& CASKey::operator=(const CASKey& rhs) noexcept {
  std::array<uint8_t, 20>::operator=(rhs);
  return *this;
}

CASKey& CASKey::operator=(CASKey&& rhs) noexcept {
  std::array<uint8_t, 20>::operator=(rhs);
  return *this;
}

uint64_t CASKey::Prefix() const {
  return static_cast<uint64_t>((*this)[0]) << 56ULL |
          static_cast<uint64_t>((*this)[1]) << 48ULL |
          static_cast<uint64_t>((*this)[2]) << 40ULL |
          static_cast<uint64_t>((*this)[3]) << 32ULL |
          static_cast<uint64_t>((*this)[4]) << 24ULL |
          static_cast<uint64_t>((*this)[5]) << 16ULL |
          static_cast<uint64_t>((*this)[6]) << 8ULL |
          static_cast<uint64_t>((*this)[7]);
}

uint64_t CASKey::Suffix() const {
  return static_cast<uint64_t>((*this)[12]) << 56ULL |
          static_cast<uint64_t>((*this)[13]) << 48ULL |
          static_cast<uint64_t>((*this)[14]) << 40ULL |
          static_cast<uint64_t>((*this)[15]) << 32ULL |
          static_cast<uint64_t>((*this)[16]) << 24ULL |
          static_cast<uint64_t>((*this)[17]) << 16ULL |
          static_cast<uint64_t>((*this)[18]) << 8ULL |
          static_cast<uint64_t>((*this)[19]);
}

std::string CASKey::ToHex() const {
  std::string result;
  cas_internal::BinaryToHex(begin(), size(), &result);
  return result;
}

}  // namespace cantera
