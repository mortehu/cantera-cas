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

#include "key.h"

#include <kj/debug.h>

#include "util.h"

namespace cantera {

CASKey CASKey::FromString(const string_view& str) {
  KJ_REQUIRE(!str.empty());

  CASKey result;

  switch (str[0]) {
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
    case 'a':
    case 'b':
    case 'c':
    case 'd':
    case 'e':
    case 'f':
    case 'A':
    case 'B':
    case 'C':
    case 'D':
    case 'E':
    case 'F':
      KJ_REQUIRE(str.size() == 40, "Hexadecimal key must be 40 characters",
                 str.size());
      cas_internal::HexToBinary(str.begin(), str.end(), result.begin());
      return result;

    case 'G':
      KJ_REQUIRE(str.size() >= 28, "Base64 key must be at least 28 characters",
                 str.size());
      cas_internal::Base64ToBinary(str.substr(1, 28), result.begin());
      return result;

    case 'P':
      KJ_FAIL_REQUIRE("Can't use CASKey::FromString with in-key objects",
                      str.to_string());

    default:
      KJ_FAIL_REQUIRE("Unknown key format", str.to_string());
  }
}

CASKey::CASKey() noexcept {}

CASKey::CASKey(const kj::ArrayPtr<const capnp::byte>& key) noexcept {
  KJ_REQUIRE(key.size() == 20, key.size());
  std::copy(key.begin(), key.end(), begin());
}

CASKey::CASKey(const uint8_t* key) noexcept {
  std::copy(key, key + 20, begin());
}

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

std::string CASKey::ToString() const {
  std::string result("G");
  cas_internal::ToBase64(
      string_view{reinterpret_cast<const char*>(data()), size()}, result,
      cas_internal::kBase64Chars, false);
  return result;
}

}  // namespace cantera
