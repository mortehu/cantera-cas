#ifndef CANTERA_BYTESTREAM_H_
#define CANTERA_BYTESTREAM_H_

#include <memory>

#include <kj/debug.h>

#include "proto/util.capnp.h"

namespace cantera {

class ByteStreamProducer : private kj::TaskSet::ErrorHandler {
 public:
  ByteStreamProducer(ByteStream::Client client)
      : client_(std::move(client)), tasks_(*this) {}

  KJ_DISALLOW_COPY(ByteStreamProducer);

  ByteStreamProducer(ByteStreamProducer&&) = default;
  ByteStreamProducer& operator=(ByteStreamProducer&&) = default;

  void Write(const void* data, size_t size) {
    auto request = client_.writeRequest();
    auto request_data = request.initData(size);
    memcpy(request_data.begin(), data, size);
    tasks_.add(request.send().ignoreResult());
  }

  void Write(kj::Array<const capnp::byte> data) {
    auto request = client_.writeRequest();
    request.setData(std::move(data));
    tasks_.add(request.send().ignoreResult().attach(std::move(data)));
  }

  kj::Promise<void> Done() {
    if (exception_) throw * exception_;

    return client_.doneRequest().send().ignoreResult();
  }

 private:
  void taskFailed(kj::Exception&& e) override {
    // TODO(mortehu): This doesn't actually do anything if we've already
    // invoked Done().

    if (!exception_) exception_ = std::make_unique<kj::Exception>(std::move(e));
  }

  ByteStream::Client client_;
  kj::TaskSet tasks_;

  std::unique_ptr<kj::Exception> exception_;
};

// Bytestream server collecting data into an std::string object.
class ByteStreamCollector : public ByteStream::Server {
 public:
  ByteStreamCollector(std::string& string) : string_(&string) {}

  ByteStreamCollector(std::shared_ptr<kj::Array<char>> array)
      : array_(std::move(array)) {}

  kj::Promise<void> write(WriteContext context) override {
    auto data = context.getParams().getData();
    if (string_) {
      string_->append(data.begin(), data.end());
    } else {
      KJ_REQUIRE(offset_ + data.size() <= array_->size(), offset_, data.size(),
                 array_->size());

      memcpy(array_->begin() + offset_, data.begin(), data.size());
      offset_ += data.size();
    }

    return kj::READY_NOW;
  }

  kj::Promise<void> done(DoneContext context) override {
    if (array_) {
      KJ_REQUIRE(offset_ == array_->size(), offset_, array_->size());
    }
    return kj::READY_NOW;
  }

  kj::Promise<void> expectSize(ExpectSizeContext context) override {
    if (string_) {
      string_->reserve(string_->size() + context.getParams().getSize());
    } else {
      KJ_REQUIRE(!offset_);
      const auto size = context.getParams().getSize();
      *array_ = kj::heapArray<char>(size);
    }
    return kj::READY_NOW;
  }

 private:
  std::string* string_ = nullptr;

  std::shared_ptr<kj::Array<char>> array_;

  size_t offset_ = 0;
};

}  // namespace cantera

#endif  // !CANTERA_BYTESTREAM_H_
