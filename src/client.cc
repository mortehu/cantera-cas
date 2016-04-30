#include "client.h"

#include <cinttypes>
#include <memory>

#include <syslog.h>

#include <kj/debug.h>

#include "bytestream.h"
#include "rpc.h"
#include "sha1.h"
#include "util.h"

namespace cantera {

class CASClient::Impl {
 public:
  Impl(kj::AsyncIoContext& aio_context)
      : aio_context{aio_context},
        cas_client{nullptr},
        on_connect{nullptr},
        on_disconnect{nullptr} {}

  // Helper function for ListAsync().
  static kj::Promise<void> ProcessList(
      CAS::ObjectList::Client list,
      std::function<void(const CASKey&)> callback);

  kj::Promise<void> Connect();

  void HandleError(kj::Exception e);

  kj::AsyncIoContext& aio_context;

  std::string addr;

  std::unique_ptr<cas_internal::RPCClient> client;

  CAS::Client cas_client;

  bool connection_pending = false;
  kj::ForkedPromise<void> on_connect;
  kj::Promise<void> on_disconnect;

  uint64_t reconnection_delay_usec = 0;

  size_t max_object_in_key_size = 128;
};

const uint64_t kDefaultReconnectionDelayUSec = 500;
const uint64_t kMaxReconnectionDelayUSec = 1'000'000;

CASClient::CASClient(kj::AsyncIoContext& aio_context)
    : pimpl_{std::make_unique<Impl>(aio_context)} {
  const auto addr = getenv("CA_CAS_SERVER");
  pimpl_->addr = addr ? addr : "localhost:6001";
}

CASClient::CASClient(kj::Own<kj::AsyncIoStream> stream,
                     kj::AsyncIoContext& aio_context)
    : pimpl_{std::make_unique<Impl>(aio_context)} {
  pimpl_->client = std::make_unique<cas_internal::RPCClient>(std::move(stream));
  pimpl_->cas_client = pimpl_->client->GetMain<CAS::Client>();
}

CASClient::CASClient(std::string addr, kj::AsyncIoContext& aio_context)
    : pimpl_{std::make_unique<Impl>(aio_context)} {
  pimpl_->addr = std::move(addr);
}

CASClient::~CASClient() {
  // TODO(mortehu): Shouldn't destructur sequencing take care of this?
  pimpl_->on_disconnect = nullptr;
}

std::string CASClient::Put(const void* data, size_t size, bool sync) {
  return PutAsync(data, size, sync).wait(pimpl_->aio_context.waitScope);
}

ByteStream::Client CASClient::PutStream(const CASKey& key, bool sync) {
  auto stream = OnConnect().then([this, key, sync]() {
    auto put_request = pimpl_->cas_client.putRequest();
    put_request.setKey(kj::arrayPtr(key.begin(), key.end()));
    put_request.setSync(sync);
    return put_request.send().getStream();
  });

  return std::move(stream);
}

kj::Promise<void> CASClient::GetStream(const string_view& key,
                                       ByteStream::Client stream) {
  KJ_REQUIRE(!key.empty());

  if (key.front() == 'P') {
    auto buffer = kj::heapArray<capnp::byte>((key.size() - 1) * 3 / 4);
    cas_internal::Base64ToBinary(key.substr(1), buffer.begin());

    auto expect_size_request = stream.expectSizeRequest();
    expect_size_request.setSize(buffer.size());
    expect_size_request.send().detach([](auto e) {});

    auto write_request = stream.writeRequest();
    write_request.setData(std::move(buffer));

    auto write_result = write_request.send();

    return write_result.attach(std::move(buffer))
        .then([stream](auto result) mutable {
          return stream.doneRequest().send().ignoreResult();
        });
  }

  auto sha1 = CASKey::FromString(key);

  return OnConnect().then([ this, sha1, stream = std::move(stream) ]() mutable {
    auto request = pimpl_->cas_client.getRequest();
    request.setKey(kj::ArrayPtr<const capnp::byte>(sha1.begin(), sha1.end()));
    request.setStream(std::move(stream));
    return request.send().ignoreResult();
  });
}

kj::Promise<void> CASClient::PutAsync(const CASKey& key, const void* data,
                                      size_t size, bool sync) {
  static const auto kWriteSize = UINT64_C(1) << 20;

  auto stream = kj::heap<ByteStreamProducer>(PutStream(key, sync));
  for (size_t offset = 0; offset < size; offset += kWriteSize) {
    auto amount = std::min(size - offset, kWriteSize);

    stream->Write(reinterpret_cast<const char*>(data) + offset, amount);
  }

  auto result = stream->Done();

  return result.attach(std::move(stream));
}

kj::Promise<std::string> CASClient::PutAsync(const void* data, size_t size,
                                             bool sync) {
  if (size < pimpl_->max_object_in_key_size) {
    std::string key("P");
    cas_internal::ToBase64(
        string_view{reinterpret_cast<const char*>(data), size}, key,
        cas_internal::kBase64Chars);
    while (key.back() == '=') key.pop_back();
    return std::move(key);
  }

  CASKey sha1;
  cas_internal::SHA1::Digest(data, size, sha1.begin());

  return PutAsync(sha1, data, size, sync).then([sha1] {
    return sha1.ToHex();
  });
}

kj::Array<const char> CASClient::Get(const string_view& key) {
  return GetAsync(key).wait(pimpl_->aio_context.waitScope);
}

kj::Promise<kj::Array<const char>> CASClient::GetAsync(const string_view& key) {
  auto result = std::make_shared<kj::Array<char>>();
  auto stream = kj::heap<ByteStreamCollector>(result);

  return GetStream(key, std::move(stream))
      .then([result = std::move(result)]() mutable {
        return kj::Array<const char>(std::move(*result));
      });
}

kj::Promise<void> CASClient::Impl::ProcessList(
    CAS::ObjectList::Client list, std::function<void(const CASKey&)> callback) {
  auto read_request = list.readRequest();
  read_request.setCount(10000);
  return read_request.send().then([
    list, callback = std::move(callback)
  ](auto response) mutable->kj::Promise<void> {
    const auto& objects = response.getObjects();

    if (!objects.size()) return kj::READY_NOW;

    for (const auto& object : objects) callback(CASKey(object.begin()));

    return Impl::ProcessList(std::move(list), callback);
  });
}

kj::Promise<void> CASClient::ListAsync(
    std::function<void(const CASKey&)> callback, CAS::ListMode mode,
    uint64_t min_size, uint64_t max_size) {
  return OnConnect().then([
    this, mode, min_size, max_size, callback = std::move(callback)
  ]() mutable {
    return ListAsync(pimpl_->cas_client, std::move(callback), mode, min_size,
                     max_size);
  });
}

kj::Promise<void> CASClient::ListAsync(
    CAS::Client& client, std::function<void(const CASKey&)> callback,
    CAS::ListMode mode, uint64_t min_size, uint64_t max_size) {
  auto request = client.listRequest();
  request.setMode(mode);
  request.setMinSize(min_size);
  request.setMaxSize(max_size);
  return Impl::ProcessList(request.send().getList(), std::move(callback));
}

kj::Promise<uint64_t> CASClient::BeginGC() {
  return OnConnect().then(
      [this]() mutable { return BeginGC(pimpl_->cas_client); });
}

kj::Promise<void> CASClient::MarkGC(const std::vector<CASKey>& keys) {
  // We can't use `OnConnect()` here, because `keys` might not be available for
  // long enough.
  return MarkGC(pimpl_->cas_client, keys);
}

kj::Promise<void> CASClient::EndGC(uint64_t id) {
  return OnConnect().then(
      [this, id]() mutable { return EndGC(pimpl_->cas_client, id); });
}

kj::Promise<uint64_t> CASClient::BeginGC(CAS::Client& client) {
  return client.beginGCRequest().send().then(
      [](auto res) -> kj::Promise<uint64_t> { return res.getId(); });
}

kj::Promise<void> CASClient::MarkGC(CAS::Client& client,
                                    const std::vector<CASKey>& keys) {
  if (keys.empty()) return kj::READY_NOW;

  auto request = client.markGCRequest();
  auto request_keys = request.initKeys(keys.size());

  for (size_t i = 0; i < keys.size(); ++i) {
    const auto& key = keys[i];
    request_keys.set(i, kj::heapArray<capnp::byte>(key.begin(), key.size()));
  }

  return request.send().ignoreResult();
}

kj::Promise<void> CASClient::EndGC(CAS::Client& client, uint64_t id) {
  auto request = client.endGCRequest();
  request.setId(id);
  return request.send().ignoreResult();
}

void CASClient::Remove(const CASKey& key) {
  return RemoveAsync(key).wait(pimpl_->aio_context.waitScope);
}

kj::Promise<void> CASClient::RemoveAsync(const CASKey& key) {
  return OnConnect().then(
      [this, key]() { return RemoveAsync(pimpl_->cas_client, key); });
}

kj::Promise<void> CASClient::RemoveAsync(CAS::Client& client,
                                         const CASKey& key) {
  auto remove_request = client.removeRequest();
  remove_request.setKey(kj::arrayPtr(key.begin(), key.end()));
  return remove_request.send().ignoreResult();
}

std::vector<CASKey> CASClient::GetBuckets() {
  return GetBucketsAsync().wait(pimpl_->aio_context.waitScope);
}

kj::Promise<std::vector<CASKey>> CASClient::GetBucketsAsync() {
  return OnConnect().then([this] {
    return pimpl_->cas_client.getConfigRequest().send().then([](auto config) {

      const auto buckets = config.getConfig().getBuckets();

      std::vector<CASKey> result;
      result.reserve(buckets.size());

      for (const auto& key : buckets) {
        KJ_REQUIRE(key.size() == 20);
        result.emplace_back(key.begin());
      }

      return std::move(result);
    });
  });
}

CASClient::Capacity CASClient::GetCapacity() {
  return GetCapacityAsync().wait(pimpl_->aio_context.waitScope);
}

kj::Promise<CASClient::Capacity> CASClient::GetCapacityAsync() {
  return OnConnect().then([this] {
    return pimpl_->cas_client.capacityRequest().send().then([](auto response) {
      Capacity result;
      result.total = response.getTotal();
      result.available = response.getAvailable();
      result.unreclaimed = response.getUnreclaimed();
      result.garbage = response.getGarbage();
      return result;
    });
  });
}

kj::Promise<void> CASClient::CompactAsync(bool sync) {
  return OnConnect().then(
      [this, sync] { return CompactAsync(pimpl_->cas_client, sync); });
}

kj::Promise<void> CASClient::CompactAsync(CAS::Client& client, bool sync) {
  auto request = client.compactRequest();
  request.setSync(sync);
  return request.send().ignoreResult();
}

CAS::Client& CASClient::RawClient() {
  if (!pimpl_->client) OnConnect().wait(pimpl_->aio_context.waitScope);

  return pimpl_->cas_client;
}

kj::WaitScope& CASClient::WaitScope() { return pimpl_->aio_context.waitScope; }

bool CASClient::Connected() const { return pimpl_->client != nullptr; }

kj::Promise<void> CASClient::OnConnect() {
  if (!pimpl_->connection_pending) return pimpl_->Connect();

  return pimpl_->on_connect.addBranch();
}

void CASClient::SetMaxObjectInKeySize(size_t limit) {
  pimpl_->max_object_in_key_size = limit;
}

kj::Promise<void> CASClient::Impl::Connect() {
  if (client) return kj::READY_NOW;

  kj::Promise<kj::Own<kj::AsyncIoStream>> stream_promise{nullptr};

  stream_promise = aio_context.provider->getNetwork().parseAddress(addr).then(
      [this](kj::Own<kj::NetworkAddress> addr)
          -> kj::Promise<kj::Own<kj::AsyncIoStream>> {
            return addr->connect().attach(std::move(addr));
          });

  on_connect =
      stream_promise
          .then([this](kj::Own<kj::AsyncIoStream> stream) {
            client =
                std::make_unique<cas_internal::RPCClient>(std::move(stream));
            cas_client = client->GetMain<CAS::Client>();
            on_disconnect =
                client->OnDisconnect()
                    .then([this]() -> kj::Promise<void> {
                      cas_client = nullptr;
                      client.reset();
                      syslog(LOG_INFO, "Lost connection to backend \"%s\"",
                             addr.c_str());
                      return Connect();
                    })
                    .eagerlyEvaluate(
                        [this](kj::Exception e) { HandleError(std::move(e)); });

            // Now that we're connected, we can set the reconnection
            // delay to its minimum value.
            reconnection_delay_usec = kDefaultReconnectionDelayUSec;
          })
          .fork();

  connection_pending = true;

  return on_connect.addBranch();
}

void CASClient::Impl::HandleError(kj::Exception e) {
  syslog(LOG_ERR, "Error connecting to \"%s\" \"%s\": %s:%d: %s", addr.c_str(),
         e.getFile(), e.getLine(), e.getDescription().cStr());

  cas_client = nullptr;
  client.reset();

  // If the server is rejecting connections because it's overloaded, we better
  // back off a bit.
  reconnection_delay_usec =
      std::max(reconnection_delay_usec * 2, kMaxReconnectionDelayUSec);
  on_disconnect = aio_context.provider->getTimer()
                      .afterDelay(reconnection_delay_usec * kj::MICROSECONDS)
                      .then([this]() -> kj::Promise<void> { return Connect(); })
                      .eagerlyEvaluate([this](kj::Exception e) {
                        HandleError(std::move(e));
                      });
}

}  // namespace cantera
