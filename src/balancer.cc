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

#include <algorithm>
#include <unordered_map>
#include <utility>
#include <vector>

#include <err.h>
#include <sysexits.h>
#include <unistd.h>

#include <capnp/ez-rpc.h>
#include <capnp/message.h>
#include <kj/arena.h>
#include <kj/debug.h>

#include "client.h"
#include "balancer.h"
#include "util.h"
#include "proto/ca-cas.capnp.h"

namespace cantera {

namespace {

class CASObjectStreamMultiplexer : public ByteStream::Server {
 public:
  CASObjectStreamMultiplexer(std::vector<ByteStream::Client> output)
      : output_(std::move(output)) {
    KJ_REQUIRE(!output_.empty());
  }

  kj::Promise<void> write(WriteContext context) override {
    auto promises = kj::heapArrayBuilder<kj::Promise<void>>(output_.size());

    auto data = kj::heapArray<capnp::byte>(context.getParams().getData());

    for (auto& o : output_) {
      auto req = o.writeRequest();
      req.setData(data);
      promises.add(req.send().ignoreResult());
    }

    return kj::joinPromises(promises.finish()).attach(std::move(data));
  }

  kj::Promise<void> done(DoneContext context) override {
    auto promises = kj::heapArrayBuilder<kj::Promise<void>>(output_.size());

    for (auto& o : output_) promises.add(o.doneRequest().send().ignoreResult());

    return kj::joinPromises(promises.finish());
  }

  kj::Promise<void> expectSize(ExpectSizeContext context) override {
    auto promises = kj::heapArrayBuilder<kj::Promise<void>>(output_.size());

    const auto size = context.getParams().getSize();

    for (auto& o : output_) {
      auto req = o.expectSizeRequest();
      req.setSize(size);
      promises.add(req.send().ignoreResult());
    }

    return kj::joinPromises(promises.finish());
  }

 private:
  std::vector<ByteStream::Client> output_;
};

class ObjectListImpl : public CAS::ObjectList::Server {
 public:
  ObjectListImpl(std::deque<CAS::ObjectList::Client>&& lists)
      : lists_(std::move(lists)) {}

  kj::Promise<void> read(ReadContext context) override;

 private:
  kj::Promise<void> Read(size_t limit);

  std::deque<CAS::ObjectList::Client> lists_;
  std::deque<CASKey> keys_;
};

kj::Promise<void> ObjectListImpl::read(ReadContext context) {
  return Read(context.getParams().getCount()).then([this, context]() mutable {
    size_t count = std::min(
        keys_.size(), static_cast<size_t>(context.getParams().getCount()));
    auto objects = context.getResults().initObjects(count);

    auto orphanage = context.getResultsOrphanage();

    for (size_t i = 0; i < count; ++i) {
      auto key_buffer = orphanage.newOrphan<capnp::Data>(20);
      std::copy(keys_.front().begin(), keys_.front().end(),
                key_buffer.get().begin());
      keys_.pop_front();
      objects.adopt(i, std::move(key_buffer));
    }
  });
}

kj::Promise<void> ObjectListImpl::Read(size_t amount) {
  if (keys_.size() >= amount || lists_.empty()) return kj::READY_NOW;

  auto read_request = lists_.front().readRequest();
  read_request.setCount(amount - keys_.size());

  return read_request.send().then(
      [this, amount](auto response) -> kj::Promise<void> {
        auto objects = response.getObjects();

        if (objects.size() == 0) lists_.pop_front();

        for (const auto& object : objects) {
          KJ_REQUIRE(object.size() == 20);
          keys_.emplace_back(object.begin());
        }

        return this->Read(amount);
      });
}

}  // namespace

kj::Promise<void> BalancerServer::beginGC(BeginGCContext context) {
  const auto& backends = sharding_info_.Backends();

  auto builder = kj::heapArrayBuilder<kj::Promise<uint64_t>>(backends.size());
  for (auto& backend : backends) {
    KJ_REQUIRE(backend.client->Connected());
    builder.add(backend.client->BeginGC());
  }

  auto responses = kj::joinPromises(builder.finish());

  return responses.then([this, context](kj::Array<uint64_t>&& ids) mutable {
    gc_id_ = std::max(gc_id_ + 1, cas_internal::CurrentTimeUSec());
    backend_gc_ids_.clear();
    backend_gc_ids_.insert(backend_gc_ids_.begin(), ids.begin(), ids.end());

    context.getResults().setId(gc_id_);
  });
}

kj::Promise<void> BalancerServer::markGC(MarkGCContext context) {
  auto request_keys = context.getParams().getKeys();

  auto arena = kj::heap<kj::Arena>(4096);

  auto key_builder =
      kj::heapArrayBuilder<capnp::Data::Reader>(request_keys.size());

  for (const auto& key : request_keys) {
    auto key_copy = arena->allocateArray<capnp::byte>(key.size());
    std::copy(key.begin(), key.end(), key_copy.begin());
    key_builder.add(std::move(key_copy));
  }

  auto keys = key_builder.finish();

  const auto& backends = sharding_info_.Backends();
  auto promise_builder =
      kj::heapArrayBuilder<kj::Promise<void>>(backends.size());

  for (auto& backend : backends) {
    KJ_REQUIRE(backend.client->Connected());
    auto request = backend.client->RawClient().markGCRequest();
    request.setKeys(keys);
    promise_builder.add(request.send().ignoreResult());
  }

  return kj::joinPromises(promise_builder.finish())
      .attach(std::move(keys))
      .attach(std::move(arena));
}

kj::Promise<void> BalancerServer::endGC(EndGCContext context) {
  const auto gc_id = context.getParams().getId();
  KJ_REQUIRE(gc_id == gc_id_, "Conflicting garbage collection detected", gc_id,
             gc_id_);

  const auto& backends = sharding_info_.Backends();
  KJ_REQUIRE(backends.size() == backend_gc_ids_.size(), backends.size(),
             backend_gc_ids_.size());

  auto builder = kj::heapArrayBuilder<kj::Promise<void>>(backends.size());

  for (size_t i = 0; i < backends.size(); ++i) {
    auto& backend = backends[i];
    KJ_REQUIRE(backend.client->Connected());

    builder.add(backend.client->EndGC(backend_gc_ids_[i]));
  }

  return kj::joinPromises(builder.finish());
}

kj::Promise<void> BalancerServer::get(GetContext context) {
  auto key_reader = context.getParams().getKey();
  KJ_REQUIRE(key_reader.size() == 20, "CASKey size must be exactly 20 bytes");

  auto key = std::make_unique<CASKey>(key_reader.begin());
  const auto offset = context.getParams().getOffset();
  const auto size = context.getParams().getSize();

  std::unordered_set<CASClient*> done;

  return GetObjectFromBackends(offset, size, std::move(key),
                               context.getParams().getStream(),
                               std::move(done));
}

kj::Promise<void> BalancerServer::put(PutContext context) {
  auto key_data = context.getParams().getKey();
  KJ_REQUIRE(key_data.size() == 20 || key_data.size() == 0, key_data.size());

  const auto sync = context.getParams().getSync();

  CASKey key(key_data);

  std::vector<CASClient*> backends;
  sharding_info_.GetWriteBackendsForKey(key, backends);

  KJ_REQUIRE(!backends.empty());

  if (backends.size() == 1) {
    auto backend = backends.front();

    auto forward_put_request = backend->RawClient().putRequest();
    forward_put_request.setKey(kj::heapArray(key_data));
    forward_put_request.setSync(sync);

    return context.tailCall(std::move(forward_put_request));
  }

  std::vector<ByteStream::Client> streams;

  for (auto& backend : backends) {
    auto forward_put_request = backend->RawClient().putRequest();
    forward_put_request.setKey(kj::heapArray(key_data));
    forward_put_request.setSync(sync);

    streams.emplace_back(forward_put_request.send().getStream());
  }

  context.getResults().setStream(
      kj::heap<CASObjectStreamMultiplexer>(std::move(streams)));

  return kj::READY_NOW;
}

kj::Promise<void> BalancerServer::remove(RemoveContext context) {
  auto key = context.getParams().getKey();
  KJ_REQUIRE(key.size() == 20, "CASKey size must be exactly 20 bytes");

  const auto& backends = sharding_info_.Backends();

  auto builder = kj::heapArrayBuilder<kj::Promise<void>>(backends.size());
  for (auto& backend : backends) {
    KJ_REQUIRE(backend.client->Connected(),
               "cannot give remove object unless all backends are connected");
    builder.add(backend.client->RemoveAsync(key.begin()));
  }

  return kj::joinPromises(builder.finish());
}

kj::Promise<void> BalancerServer::capacity(CapacityContext context) {
  const auto& backends = sharding_info_.Backends();
  auto builder =
      kj::heapArrayBuilder<kj::Promise<CASClient::Capacity>>(backends.size());
  for (auto& backend : backends)
    builder.add(backend.client->GetCapacityAsync());

  auto responses = kj::joinPromises(builder.finish());

  return responses.then([context](auto capacities) mutable {
    uint64_t total = 0, available = 0, unreclaimed = 0, garbage = 0;
    for (auto& capacity : capacities) {
      total += capacity.total;
      available += capacity.available;
      unreclaimed += capacity.unreclaimed;
      garbage += capacity.garbage;
    }
    context.getResults().setTotal(total);
    context.getResults().setAvailable(available);
    context.getResults().setUnreclaimed(unreclaimed);
    context.getResults().setGarbage(garbage);
  });
}

kj::Promise<void> BalancerServer::list(ListContext context) {
  const auto mode = context.getParams().getMode();
  const auto min_size = context.getParams().getMinSize();
  const auto max_size = context.getParams().getMaxSize();

  std::deque<CAS::ObjectList::Client> lists;

  for (auto& backend : sharding_info_.Backends()) {
    KJ_REQUIRE(backend.client->Connected(),
               "cannot list objects unless all backends are connected");
    auto request = backend.client->RawClient().listRequest();
    request.setMode(mode);
    request.setMinSize(min_size);
    request.setMaxSize(max_size);
    lists.emplace_back(request.send().getList());
  }

  context.getResults().setList(kj::heap<ObjectListImpl>(std::move(lists)));

  return kj::READY_NOW;
}

kj::Promise<void> BalancerServer::compact(CompactContext context) {
  // Maps failure domain to promise for that domain.  We create one chain of
  // promises per failure domain, and run each chain in parallel.
  std::unordered_map<uint8_t, kj::Promise<void>> promises;

  for (auto& backend : sharding_info_.Backends()) {
    if (!backend.client->Connected()) continue;

    auto i = promises.find(backend.failure_domain);

    // TODO(mortehu): Keep going on error.

    if (i == promises.end()) {
      promises.emplace(backend.failure_domain, backend.client->CompactAsync());
    } else {
      i->second = i->second.then(
          [client = backend.client] { return client->CompactAsync(); });
    }
  }

  auto promise_array = kj::heapArrayBuilder<kj::Promise<void>>(promises.size());

  for (auto& promise : promises) promise_array.add(std::move(promise.second));

  return kj::joinPromises(promise_array.finish());
}

kj::Promise<void> BalancerServer::getConfig(GetConfigContext context) {
  size_t bucket_count = 0;

  for (const auto& backend : sharding_info_.Backends())
    bucket_count += backend.buckets.size();

  auto config = context.getResults().initConfig();

  auto config_buckets = config.initBuckets(bucket_count);

  size_t i = 0;

  for (const auto& backend : sharding_info_.Backends()) {
    for (const auto& bucket : backend.buckets)
      config_buckets.set(i++, kj::arrayPtr(bucket.begin(), bucket.size()));
  }

  return kj::READY_NOW;
}

kj::Promise<void> BalancerServer::GetObjectFromBackends(
    uint64_t offset, uint64_t size, std::unique_ptr<CASKey> key,
    ByteStream::Client stream, std::unordered_set<CASClient*> done) {
  auto backend = sharding_info_.NextShardForKey(*key, done);
  done.emplace(backend);

  KJ_ASSERT(backend->Connected());

  auto get_request = backend->RawClient().getRequest();

  get_request.setOffset(offset);
  get_request.setSize(size);
  get_request.setKey(kj::arrayPtr(key->begin(), key->end()));
  get_request.setStream(stream);

  return get_request.send().then(
      [](auto get_results) mutable -> kj::Promise<void> {
        return kj::READY_NOW;
      },
      [
        offset, size, key = std::move(key), stream, done = std::move(done), this
      ](kj::Exception && e) mutable {
        return GetObjectFromBackends(offset, size, std::move(key), stream,
                                     std::move(done));
      });
}

}  // namespace cantera
