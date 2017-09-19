#ifndef CANTERA_CAS_CLIENT_H_
#define CANTERA_CAS_CLIENT_H_ 1

#include <array>
#include <cstdint>
#include <functional>
#include <string_view>
#include <memory>
#include <vector>

#include <capnp/common.h>
#include <kj/arena.h>
#include <kj/array.h>
#include <kj/async-io.h>
#include <kj/debug.h>

#include "key.h"
#include "proto/ca-cas.capnp.h"

namespace cantera {

// A simplified interface for talking to the CAS servers.
class CASClient {
 public:
  struct Capacity {
    size_t total = 0;
    size_t available = 0;
    size_t unreclaimed = 0;
    size_t garbage = 0;
  };

  static kj::Promise<void> ListAsync(
      CAS::Client& client, std::function<void(const CASKey&)> callback,
      CAS::ListMode mode = CAS::ListMode::DEFAULT, uint64_t min_size = 0,
      uint64_t max_size = UINT64_C(0xffffffffffffffff));

  static kj::Promise<uint64_t> BeginGC(CAS::Client& client);
  static kj::Promise<void> MarkGC(CAS::Client& client,
                                  const std::vector<CASKey>& keys);
  static kj::Promise<void> EndGC(CAS::Client& client, uint64_t id);

  static kj::Promise<void> RemoveAsync(CAS::Client& client, const CASKey& key);

  static kj::Promise<void> CompactAsync(CAS::Client& client, bool sync = true);

  // Creates a client using the default server name.
  CASClient(kj::AsyncIoContext& aio_context);

  // Creates a client from an already established connection.
  //
  // Note that this type of client will not automatically reconnect, and will
  // instead throw exceptions on all requests after the stream is disconnected.
  // This constructor's primary purpose is unit testing.
  //
  // It's assumed that the stream belongs to the ev::AsyncIoContext() context.
  CASClient(kj::Own<kj::AsyncIoStream> stream, kj::AsyncIoContext& aio_context);

  // Creates a client for connecting to the given address.
  CASClient(std::string addr, kj::AsyncIoContext& aio_context);

  ~CASClient();

  KJ_DISALLOW_COPY(CASClient);

  // Returns a stream for writing to CAS with the given key.  Throws an
  // exception on failure.  Failures can happen for any and no reason, so it's
  // important that the caller has retry logic.
  cantera::ByteStream::Client PutStream(const CASKey& key, bool sync = true);

  // Reads the given object from CAS into the given stream.  Throws an
  // exception on failure.  Failures can happen for any and no reason, so it's
  // important that the caller has retry logic.
  kj::Promise<void> GetStream(const std::string_view& key,
                              cantera::ByteStream::Client stream);

  // Puts data into CAS.  All of these functions are convience wrappers for
  // `PutStream`.
  std::string Put(const void* data, size_t size, bool sync = true);

  std::string Put(const std::string_view& data, bool sync = true) {
    return Put(data.data(), data.size(), sync);
  }

  template <typename T>
  std::string Put(const kj::Array<T>& data, bool sync = true) {
    static_assert(sizeof(T) == 1, "");
    return Put(reinterpret_cast<const char*>(data.begin()), data.size(), sync);
  }

  kj::Promise<void> PutAsync(const CASKey& key, const void* data, size_t size,
                             bool sync = true);

  kj::Promise<std::string> PutAsync(const void* data, size_t size,
                                    bool sync = true);

  kj::Promise<std::string> PutAsync(const std::string_view& data, bool sync = true) {
    return PutAsync(data.data(), data.size(), sync);
  }

  // Reads data from CAS.  All of these functions are convenience wrappers for
  // `GetStream`.
  kj::Array<const char> Get(const std::string_view& key);
  kj::Promise<kj::Array<const char>> GetAsync(const std::string_view& key);

  // Retrieves a list of all keys stored on the server.
  kj::Promise<void> ListAsync(std::function<void(const CASKey&)> callback,
                              CAS::ListMode mode = CAS::ListMode::DEFAULT,
                              uint64_t min_size = 0,
                              uint64_t max_size = UINT64_C(0xffffffffffffffff));

  kj::Promise<uint64_t> BeginGC();
  kj::Promise<void> MarkGC(const std::vector<CASKey>& keys);
  kj::Promise<void> EndGC(uint64_t id);

  void Remove(const CASKey& key);
  kj::Promise<void> RemoveAsync(const CASKey& key);

  std::vector<CASKey> GetBuckets();
  kj::Promise<std::vector<CASKey>> GetBucketsAsync();

  Capacity GetCapacity();
  kj::Promise<Capacity> GetCapacityAsync();

  kj::Promise<void> CompactAsync(bool sync = true);

  CAS::Client& RawClient();
  kj::WaitScope& WaitScope();

  bool Connected() const;

  kj::Promise<void> OnConnect();

  // Set the size of the largest object that is allowed to be stored directly
  // in the key, plus one.  If set to zero, no object is ever stored in the key
  // itself.
  void SetMaxObjectInKeySize(size_t limit);

 private:
  class Impl;
  std::unique_ptr<Impl> pimpl_;
};

}  // namespace cantera

#endif  // !STORAGE_CA_CAS_CLIENT_H_
