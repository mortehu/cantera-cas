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

#include <kj/debug.h>
#include <yaml-cpp/yaml.h>

#include "src/sharding.h"
#include "src/util.h"

namespace cantera {
namespace cas_internal {

ShardingInfo::ShardingInfo(kj::AsyncIoContext& aio_context)
    : aio_context_{aio_context} {}

ShardingInfo::ShardingInfo(const std::string& filename,
                           kj::AsyncIoContext& aio_context)
    : aio_context_{aio_context} {
  auto config_root = YAML::LoadFile(filename);

  auto config_replicas = config_root["replicas"];
  if (config_replicas.IsDefined()) {
    KJ_REQUIRE(config_replicas.IsScalar());
    full_replicas_ = config_replicas.as<size_t>();
  }

  auto config_backends = config_root["backends"];
  KJ_REQUIRE(config_backends.IsSequence());

  for (const auto& config_backend : config_backends) {
    Backend backend;

    const auto addr = config_backend["addr"];
    KJ_REQUIRE(addr.IsScalar());
    backend.addr = addr.Scalar();

    auto failure_domain = config_backend["failure-domain"];
    if (failure_domain.IsDefined()) {
      KJ_REQUIRE(failure_domain.IsScalar());
      backend.failure_domain = failure_domain.as<int>();
    }

    KJ_CONTEXT(backend.addr, backend.failure_domain);

    backend.client = std::make_unique<CASClient>(backend.addr, aio_context);
    backend.client->OnConnect().wait(aio_context_.waitScope);

    InitializeBackend(backend);
  }
}

void ShardingInfo::AddBackend(std::shared_ptr<CASClient> client,
                              uint8_t failure_domain) {
  Backend backend;
  backend.client = std::move(client);
  backend.failure_domain = failure_domain;

  InitializeBackend(backend);
}

void ShardingInfo::GetWriteBackendsForKey(const CASKey& key,
                                          std::vector<CASClient*>& result) {
  KJ_REQUIRE(backends_.size() >= full_replicas_);

  uint64_t failure_domain_mask = ~static_cast<uint64_t>(0);
  std::unordered_set<CASClient*> done;

  const auto first = FirstBackendForKey(key);

  auto i = first;

  while (result.size() < full_replicas_) {
    const auto& backend = backends_[i->second];
    const auto shard_mask = UINT64_C(1) << backend.failure_domain;

    if ((shard_mask & failure_domain_mask) != 0 &&
        backend.client->Connected() && !done.count(backend.client.get())) {
      result.emplace_back(backend.client.get());
      done.emplace(backend.client.get());

      failure_domain_mask &= ~shard_mask;
    }

    if (result.size() == full_replicas_) break;

    if (++i == hash_ring_.end()) i = hash_ring_.begin();
    KJ_REQUIRE(i != first, "Not enough online backends", result.size(),
               full_replicas_, backends_.size());
  }
}

CASClient* ShardingInfo::NextShardForKey(
    const CASKey& key, const std::unordered_set<CASClient*>& done) {
  const auto first = FirstBackendForKey(key);

  auto i = first;

  do {
    const auto& backend = backends_[i->second];
    if (!done.count(backend.client.get()) && backend.client->Connected())
      return backend.client.get();

    if (++i == hash_ring_.end()) i = hash_ring_.begin();
  } while (i != first);

  KJ_FAIL_REQUIRE("Missing backend for key");
}

void ShardingInfo::InitializeBackend(Backend backend) {
  const auto idx = backends_.size();
  auto config = backend.client->RawClient().getConfigRequest().send().wait(
      aio_context_.waitScope);

  const auto old_ring_size = hash_ring_.size();

  auto cmp = [](const auto& lhs, const auto& rhs) {
    return lhs.first < rhs.first;
  };

  for (const auto& key : config.getConfig().getBuckets()) {
    KJ_REQUIRE(key.size() == 20);
    backend.buckets.emplace_back(key.begin());
    hash_ring_.emplace_back(key.begin(), idx);
  }

  std::sort(hash_ring_.begin() + old_ring_size, hash_ring_.end(), cmp);

  std::inplace_merge(hash_ring_.begin(), hash_ring_.begin() + old_ring_size,
                     hash_ring_.end(), cmp);

  backends_.emplace_back(std::move(backend));
}

ShardingInfo::HashRing::const_iterator ShardingInfo::FirstBackendForKey(
    const CASKey& key) const {
  KJ_REQUIRE(!hash_ring_.empty());

  auto result = std::lower_bound(
      hash_ring_.begin(), hash_ring_.end(), key,
      [](const auto& lhs, const CASKey& rhs) { return lhs.first < rhs; });

  if (result == hash_ring_.end()) result = hash_ring_.begin();

  return result;
}

}  // namespace cas_internal
}  // namespace cantera
