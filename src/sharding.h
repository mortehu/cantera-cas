#ifndef STORAGE_CA_CAS_SHARDING_H_
#define STORAGE_CA_CAS_SHARDING_H_ 1

#include <unordered_set>

#include <kj/async-io.h>

#include "client.h"

namespace cantera {

class ShardingInfo {
 public:
  struct Backend {
    std::string addr;
    uint8_t failure_domain = 0;

    std::shared_ptr<CASClient> client;

    std::vector<CASKey> buckets;
  };

  ShardingInfo(kj::AsyncIoContext& aio_context);
  ShardingInfo(const std::string& filename, kj::AsyncIoContext& aio_context);

  ShardingInfo(ShardingInfo&&) = default;
  ShardingInfo& operator=(ShardingInfo&&) = default;

  KJ_DISALLOW_COPY(ShardingInfo);

  const std::vector<Backend>& Backends() const { return backends_; }

  size_t FullReplicas() const { return full_replicas_; }

  void AddBackend(std::shared_ptr<CASClient> client, uint8_t failure_domain);

  void SetFullReplicas(size_t n) { full_replicas_ = n; }

  // Determines to which backends an object should be written.  The results are
  // written to the `result` vector.
  void GetWriteBackendsForKey(const CASKey& key,
                              std::vector<CASClient*>& result);

  // Determines the next candidate for reading a previously stored object.  The
  // `done` parameter should indicate which backends have already been
  // attempted.
  CASClient* NextShardForKey(const CASKey& key,
                             const std::unordered_set<CASClient*>& done);

  size_t BucketCount() const { return hash_ring_.size(); }

 private:
  typedef std::vector<std::pair<CASKey, size_t>> HashRing;

  void InitializeBackend(Backend backend);

  HashRing::const_iterator FirstBackendForKey(const CASKey& key) const;

  kj::AsyncIoContext& aio_context_;

  size_t full_replicas_ = 1;

  std::vector<Backend> backends_;

  HashRing hash_ring_;
};

}  // namespace cantera

#endif  // !STORAGE_CA_CAS_SHARDING_H_
