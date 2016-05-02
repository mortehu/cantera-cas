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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <mutex>

#include <fcntl.h>
#include <syslog.h>
#include <unistd.h>

#include <capnp/rpc-twoparty.h>
#include <kj/debug.h>

#include "src/async-io.h"

namespace cantera {
namespace cas_internal {

namespace {

// TODO(mortehu): Verify that this never leaks.
struct SignalArgument {
  AsyncIOServer* aio_server;
  size_t event_id;
};

std::mutex mutex;

std::unordered_map<size_t, AsyncIOServer::IORequest*> pending_requests;
size_t next_id;

void SignalHandler(sigval_t val) {
  try {
    auto arg = reinterpret_cast<SignalArgument*>(val.sival_ptr);
    arg->aio_server->PostEvent(arg->event_id);
    delete arg;
  } catch (kj::Exception e) {
    syslog(LOG_ERR, "Failed to write to event fd: %s:%d: %s", e.getFile(),
           e.getLine(), e.getDescription().cStr());
  }
}

}  // namespace

AsyncIOServer::AsyncIOServer(kj::AsyncIoContext& async_io)
    : event_promise_(nullptr) {
  int pipe[2];
  KJ_SYSCALL(::pipe2(pipe, O_CLOEXEC));
  event_writer_ = kj::AutoCloseFd(pipe[1]);
  event_reader_ = async_io.lowLevelProvider->wrapInputFd(pipe[0]);
  event_promise_ =
      event_reader_->read(&id_buffer_, sizeof(id_buffer_), sizeof(id_buffer_))
          .then([this](auto size) mutable {
            return this->HandleEvent(id_buffer_);
          });
}

std::pair<kj::Own<RPCClient>, kj::Own<RPCServer<AsyncIO>>>
AsyncIOServer::Create(kj::AsyncIoContext& async_io) {
  auto pipe = async_io.provider->newTwoWayPipe();

  return std::make_pair(
      kj::heap<RPCClient>(std::move(pipe.ends[0])),
      kj::heap<RPCServer<AsyncIO>>(kj::heap<AsyncIOServer>(async_io),
                                   std::move(pipe.ends[1])));
}

kj::Promise<void> AsyncIOServer::pread(PreadContext context) {
  auto params = context.getParams();
  auto fd = params.getFd();
  static_assert(sizeof(char*) == sizeof(params.getBuffer()),
                "expected 64-bit pointers");
  auto buf = reinterpret_cast<char*>(params.getBuffer());
  auto start = params.getStart();
  auto length = params.getLength();

  if (!length) return kj::READY_NOW;

  return kj::newAdaptedPromise<void, IORequest>(IORequest::kOperationRead, this,
                                                fd, buf, start, length);
}

kj::Promise<void> AsyncIOServer::pwrite(PwriteContext context) {
  auto params = context.getParams();
  auto fd = params.getFd();
  static_assert(sizeof(const char*) == sizeof(params.getBuffer()),
                "expected 64-bit pointers");
  auto buf = reinterpret_cast<const char*>(params.getBuffer());
  auto start = params.getStart();
  auto length = params.getLength();

  if (!length) return kj::READY_NOW;

  return kj::newAdaptedPromise<void, IORequest>(
      IORequest::kOperationWrite, this, fd, const_cast<char*>(buf), start,
      length);
}

kj::Promise<void> AsyncIOServer::fsync(FsyncContext context) {
  return kj::newAdaptedPromise<void, IORequest>(
      IORequest::kOperationFsync, this, context.getParams().getFd());
}

AsyncIOServer::IORequest::IORequest(kj::PromiseFulfiller<void>& fulfiller,
                                    Operation operation,
                                    AsyncIOServer* aio_server, int fd,
                                    void* dest, size_t offset, size_t length)
    : fulfiller_(fulfiller),
      operation_(operation),
      fd_(fd),
      offset_(offset),
      length_(length) {
  std::unique_lock<std::mutex> lk(mutex);
  id_ = next_id++;

  auto arg = new SignalArgument;
  arg->aio_server = aio_server;
  arg->event_id = id_;

  memset(&aiocb_, 0, sizeof(aiocb_));
  aiocb_.aio_fildes = fd;
  aiocb_.aio_buf = dest;
  aiocb_.aio_offset = offset;
  aiocb_.aio_nbytes = length;
  aiocb_.aio_sigevent.sigev_notify = SIGEV_THREAD;
  aiocb_.aio_sigevent.sigev_notify_function = SignalHandler;
  aiocb_.aio_sigevent.sigev_value.sival_ptr = arg;
  pending_requests[id_] = this;

  lk.unlock();

  switch (operation) {
    case kOperationFsync:
      KJ_SYSCALL(aio_fsync(O_SYNC, &aiocb_));
      break;

    case kOperationRead:
      KJ_SYSCALL(aio_read(&aiocb_));
      break;

    case kOperationWrite:
      KJ_SYSCALL(aio_write(&aiocb_));
      break;

    default:
      KJ_FAIL_REQUIRE("Unknown I/O operation", operation);
  }
}

AsyncIOServer::IORequest::~IORequest() {
  // First make sure we're not accessed from another thread.
  std::unique_lock<std::mutex> lk(mutex);
  pending_requests.erase(id_);
  lk.unlock();

  if (done_) return;

  switch (aio_cancel(fd_, &aiocb_)) {
    case AIO_NOTCANCELED: {
      const aiocb* aiocb_list[] = {&aiocb_};
      KJ_SYSCALL(aio_suspend(aiocb_list, 1, nullptr));
      KJ_REQUIRE(EINPROGRESS != aio_error(&aiocb_));
    } break;

    case AIO_CANCELED:
      delete reinterpret_cast<SignalArgument*>(
          aiocb_.aio_sigevent.sigev_value.sival_ptr);
  }
}

void AsyncIOServer::IORequest::HandleCompletion() {
  fulfiller_.rejectIfThrows([this]() mutable {
    auto error = aio_error(&aiocb_);

    ssize_t result = -1;
    if (error != EINPROGRESS) {
      done_ = true;
      result = aio_return(&aiocb_);
    }

    if (error != 0) {
      KJ_FAIL_SYSCALL("aio", error, operation_, fd_, offset_, length_);
    }

    KJ_REQUIRE(static_cast<size_t>(result) == length_, result, length_);

    fulfiller_.fulfill();
  });
}

void AsyncIOServer::PostEvent(size_t id) {
  kj::FdOutputStream event_output(event_writer_.get());
  event_output.write(&id, sizeof(id));
}

kj::Promise<void> AsyncIOServer::HandleEvent(size_t id) {
  std::unique_lock<std::mutex> lk(mutex);

  auto i = pending_requests.find(id);

  if (i != pending_requests.end()) i->second->HandleCompletion();

  return event_reader_
      ->read(&id_buffer_, sizeof(id_buffer_), sizeof(id_buffer_))
      .then(
          [this](auto size) mutable { return this->HandleEvent(id_buffer_); });
}

}  // namespace cas_internal
}  // namespace cantera
