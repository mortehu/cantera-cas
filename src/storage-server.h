#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <capnp/serialize.h>
#include <kj/array.h>
#include <kj/async-io.h>

#include "client.h"
#include "proto/async-io.capnp.h"
#include "proto/ca-cas.capnp.h"
#include "rpc.h"

namespace cantera {
namespace cas_internal {

class PackManager;

class StorageServer : public CAS::Server {
 public:
  enum Flag : unsigned int {
    kDisableRead = 1,
  };

  struct IndexEntry {
    IndexEntry() = default;

    IndexEntry(const CASKey& key) : key(key) {}

    uint64_t offset = 0;
    uint32_t size = 0;
    CASKey key;

    bool operator==(const IndexEntry& rhs) const { return key == rhs.key; }
  };

  struct IndexEntryHash {
    typedef std::size_t value_type;

    value_type operator()(const IndexEntry& v) const {
      return std::hash<CASKey>()(v.key);
    }
  };

  StorageServer(const char* path, unsigned int flags,
                kj::AsyncIoContext& aio_context);

  KJ_DISALLOW_COPY(StorageServer);
  ~StorageServer();

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

  kj::Promise<void> Put(const CASKey& key, std::string data, bool sync);

  const std::unordered_set<StorageServer::IndexEntry,
                           StorageServer::IndexEntryHash>&
  Index() const {
    return index_;
  }

  const std::unordered_set<CASKey>& Marks() const { return marks_; }

 private:
  // Calls `fdatasync(2)` asynchrounously on `fd`.
  kj::Promise<void> DataSync(int fd);

  kj::Promise<void> CompactIndexFile(bool sync);

  kj::Promise<void> DrainDataFile(std::vector<IndexEntry> moves);

  void ReadIndex();

  std::vector<size_t> GetUnreclaimedSpace();

  kj::AsyncIoContext& aio_context_;

  std::pair<kj::Own<cas_internal::RPCClient>,
            kj::Own<cas_internal::RPCServer<AsyncIO>>>
      aio_;
  AsyncIO::Client aio_client_;

  kj::AutoCloseFd dir_fd_;

  // Descriptor for file holding index entries.
  kj::AutoCloseFd index_fd_;

  // Descriptor for files holding object data.
  std::vector<kj::AutoCloseFd> data_fds_;
  std::vector<std::pair<size_t, size_t>> data_file_sizes_;
  std::unordered_map<size_t, size_t> data_file_utilization_;

  std::unordered_set<IndexEntry, IndexEntryHash> index_;

  // Marks used in mark and sweep garbage collection.
  std::unordered_set<CASKey> marks_;
  uint64_t gc_id_ = 0;

  // Total size of marked objects.
  size_t garbage_size_ = 0;

  kj::Array<const char> config_data_;

  bool disable_read_ = false;

  // Set to true whenever an object is removed, to indicate that the index
  // could benefit from compaction.
  bool index_dirty_ = false;

  // Index of data file being compacted, or -1 if no compaction is currently in
  // progress.
  int compacting_data_file_ = -1;
};

}  // namespace cas_internal
}  // namespace cantera
