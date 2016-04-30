#include <deque>
#include <memory>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <capnp/ez-rpc.h>

#include "client.h"
#include "proto/ca-cas.capnp.h"
#include "sharding.h"

namespace cantera {

class BalancerServer : public CAS::Server {
 public:
  KJ_DISALLOW_COPY(BalancerServer);

  BalancerServer(kj::AsyncIoContext& aio_context)
      : sharding_info_{aio_context} {}
  BalancerServer(const std::string& filename, kj::AsyncIoContext& aio_context)
      : sharding_info_{filename, aio_context} {}

  BalancerServer(BalancerServer&&) = default;
  BalancerServer& operator=(BalancerServer&&) = default;

  void AddBackend(std::shared_ptr<CASClient> client, uint8_t failure_domain) {
    sharding_info_.AddBackend(std::move(client), failure_domain);
  }

  void SetReplicas(size_t n) { sharding_info_.SetFullReplicas(n); }

  kj::Promise<void> beginGC(BeginGCContext context) override;

  kj::Promise<void> markGC(MarkGCContext context) override;

  kj::Promise<void> endGC(EndGCContext context) override;

  kj::Promise<void> get(GetContext context) override;

  kj::Promise<void> put(PutContext context) override;

  kj::Promise<void> remove(RemoveContext context) override;

  kj::Promise<void> capacity(CapacityContext context) override;

  kj::Promise<void> list(ListContext context) override;

  kj::Promise<void> compact(CompactContext context) override;

  kj::Promise<void> getConfig(GetConfigContext context) override;

 private:
  kj::Promise<void> GetObjectFromBackends(uint64_t offset, uint64_t size,
                                          std::unique_ptr<CASKey> key,
                                          ByteStream::Client stream,
                                          std::unordered_set<CASClient*> done);

  ShardingInfo sharding_info_;

  std::vector<uint64_t> backend_gc_ids_;
  uint64_t gc_id_ = 0;
};

}  // namespace cantera
