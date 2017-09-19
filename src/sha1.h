// Copyright 2016 Morten Hustveit <morten.hustveit@gmail.com>
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
//
// In addition, as a special exception, the copyright holders give
// permission to link the code of portions of this program with the
// OpenSSL library under certain conditions as described in each
// individual source file, and distribute linked combinations
// including the two.
//
// You must obey the GNU General Public License in all respects
// for all of the code used other than OpenSSL.  If you modify
// file(s) with this exception, you may extend this exception to your
// version of the file(s), but you are not obligated to do so.  If you
// do not wish to do so, delete this exception statement from your
// version.  If you delete this exception statement from all source
// files in the program, then also delete it here.

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
