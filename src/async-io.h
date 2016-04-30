#ifndef STORAGE_ASYNC_ASYNC_IO_H_
#define STORAGE_ASYNC_ASYNC_IO_H_ 1

#include <unordered_map>

#include <aio.h>
#include <signal.h>

#include <kj/async-io.h>
#include <kj/io.h>

#include "proto/async-io.capnp.h"
#include "rpc.h"

namespace cantera {
namespace cas_internal {

class AsyncIOServer : public AsyncIO::Server {
 public:
  class IORequest {
   public:
    enum Operation {
      kOperationFsync = 'f',
      kOperationRead = 'r',
      kOperationWrite = 'w',
    };

    IORequest(kj::PromiseFulfiller<void>& fulfiller, Operation operation,
              AsyncIOServer* aio_server, int fd, void* dest = nullptr,
              size_t offset = 0, size_t length = 0);

    ~IORequest();

    void HandleCompletion();

   private:
    kj::PromiseFulfiller<void>& fulfiller_;

    Operation operation_;

    int fd_;
    size_t offset_;
    size_t length_;

    bool done_ = false;

    aiocb aiocb_;
    size_t id_;
  };

  static std::pair<kj::Own<RPCClient>, kj::Own<RPCServer<AsyncIO>>> Create(
      kj::AsyncIoContext& async_io);

  AsyncIOServer(kj::AsyncIoContext& async_io);

  kj::Promise<void> pread(PreadContext context) override;

  kj::Promise<void> pwrite(PwriteContext context) override;

  kj::Promise<void> fsync(FsyncContext context) override;

  void PostEvent(size_t id);

 private:
  kj::Promise<void> HandleEvent(size_t id);

  kj::Own<kj::AsyncInputStream> event_reader_;
  kj::AutoCloseFd event_writer_;
  size_t id_buffer_;

  kj::Promise<void> event_promise_;
};

}  // namespace cas_internal
}  // namespace cantera

#endif  // !STORAGE_ASYNC_ASYNC_IO_H_
