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

#include "src/storage-server.h"

#include <algorithm>
#include <cerrno>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <random>
#include <thread>
#include <utility>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#if HAVE_SYS_VFS_H
#include <sys/vfs.h>
#else
#include <sys/param.h>
#include <sys/mount.h>
#endif
#include <syslog.h>
#include <unistd.h>

#include <capnp/message.h>
#include <capnp/schema.h>
#include <capnp/serialize.h>
#include <kj/debug.h>

#include "async-io.h"
#include "client.h"
#include "io.h"
#include "proto/ca-cas.capnp.h"
#include "sha1.h"

namespace cantera {
namespace cas_internal {

namespace {

const auto kBucketMask = UINT64_C(0x3f00000000000000);
const auto kDeletedMask = UINT64_C(0x8000000000000000);
const auto kOffsetMask = UINT64_C(0x00ffffffffffffff);

const size_t kHashBucketSize = 128 * 1024 * 1024;

bool HeapComparator(const std::pair<size_t, size_t>& lhs,
                    const std::pair<size_t, size_t>& rhs) {
  return lhs.first > rhs.first;
}

// Stream similar to writing to /dev/null.
class NullStream : public ByteStream::Server {
 public:
  NullStream(StorageServer& storage_server) : storage_server_(storage_server) {}

  kj::Promise<void> write(WriteContext context) override {
    return kj::READY_NOW;
  }

  kj::Promise<void> done(DoneContext context) override { return kj::READY_NOW; }

  kj::Promise<void> expectSize(ExpectSizeContext context) override {
    return kj::READY_NOW;
  }

 private:
  StorageServer& storage_server_;
};

class PutStream : public ByteStream::Server {
 public:
  PutStream(StorageServer& storage_server, CASKey key, bool sync);

  kj::Promise<void> write(WriteContext context) override;

  kj::Promise<void> done(DoneContext context) override;

  kj::Promise<void> expectSize(ExpectSizeContext context) override;

 private:
  StorageServer& storage_server_;

  CASKey sha1_digest_;

  bool sync_;

  std::string buffer_;

  cas_internal::SHA1 sha1_;
};

class ObjectListImpl : public CAS::ObjectList::Server {
 public:
  ObjectListImpl(const StorageServer* server, CAS::ListMode mode,
                 uint64_t min_size, uint64_t max_size);

  kj::Promise<void> read(ReadContext context) override;

 private:
  std::deque<StorageServer::IndexEntry> buffer_;
};

PutStream::PutStream(StorageServer& storage_server, CASKey key, bool sync)
    : storage_server_(storage_server), sha1_digest_(key), sync_(sync) {}

kj::Promise<void> PutStream::write(WriteContext context) {
  auto data = context.getParams().getData();

  sha1_.Add(data.begin(), data.size());
  buffer_.append(data.begin(), data.end());

  return kj::READY_NOW;
}

kj::Promise<void> PutStream::done(DoneContext context) {
  CASKey calc_sha1_digest;
  sha1_.Finish(calc_sha1_digest.begin());

  KJ_REQUIRE(std::equal(calc_sha1_digest.begin(), calc_sha1_digest.end(),
                        sha1_digest_.begin()),
             "calculated SHA-1 digest does not match key suggested by client");

  return storage_server_.Put(sha1_digest_, std::move(buffer_), sync_);
}

kj::Promise<void> PutStream::expectSize(ExpectSizeContext context) {
  buffer_.reserve(buffer_.size() + context.getParams().getSize());
  return kj::READY_NOW;
}

ObjectListImpl::ObjectListImpl(const StorageServer* server, CAS::ListMode mode,
                               uint64_t min_size, uint64_t max_size) {
  const auto& index = server->Index();
  buffer_.assign(index.begin(), index.end());

  buffer_.erase(std::remove_if(buffer_.begin(), buffer_.end(),
                               [min_size, max_size](const auto& ie) {
                                 return ie.size < min_size ||
                                        ie.size >= max_size;
                               }),
                buffer_.end());

  if (mode == CAS::ListMode::GARBAGE) {
    const auto& marks = server->Marks();
    buffer_.erase(std::remove_if(buffer_.begin(), buffer_.end(),
                                 [&marks](const auto& ie) {
                                   return !marks.count(ie.key);
                                 }),
                  buffer_.end());
  }

  std::sort(
      buffer_.begin(), buffer_.end(),
      [](const auto& lhs, const auto& rhs) { return lhs.offset < rhs.offset; });
}

kj::Promise<void> ObjectListImpl::read(ReadContext context) {
  auto count = context.getParams().getCount();

  if (buffer_.size() < count) count = buffer_.size();

  auto objects = context.getResults().initObjects(count);

  auto bi = buffer_.begin();

  auto orphanage = context.getResultsOrphanage();

  for (size_t i = 0; i < count; ++i, ++bi) {
    auto key_buffer = orphanage.newOrphan<capnp::Data>(20);
    memcpy(key_buffer.get().begin(), bi->key.begin(), 20);
    objects.adopt(i, std::move(key_buffer));
  }

  buffer_.erase(buffer_.begin(), bi);

  return kj::READY_NOW;
}

kj::Promise<void> WriteStream(ByteStream::Client&& stream,
                              AsyncIO::Client& aio_client, int fd,
                              size_t offset, size_t size) {
  // TODO(mortehu): Implement double-buffering.

  KJ_ASSERT(offset <= size, offset, size);

  static const size_t kBufferSize = 8 * 1024 * 1024;

  if (offset == size) return stream.doneRequest().send().ignoreResult();

  const auto read_amount = std::min(size - offset, kBufferSize);

  auto data = kj::heapArray<capnp::byte>(read_amount);

  auto pread_request = aio_client.preadRequest();
  pread_request.setFd(fd);
  pread_request.setBuffer(reinterpret_cast<uint64_t>(data.begin()));
  pread_request.setStart(offset);
  pread_request.setLength(read_amount);

  offset += read_amount;

  return pread_request.send().then([
    stream = std::move(stream), aio_client, fd, offset, size,
    data = std::move(data)
  ](auto read_response) mutable {
    auto write_request = stream.writeRequest();
    write_request.setData(data);

    return write_request.send().attach(std::move(data)).then([
      stream = std::move(stream), aio_client, fd, offset, size
    ](auto write_response) mutable {
      return WriteStream(std::move(stream), aio_client, fd, offset, size);
    });
  });
}

}  // namespace

StorageServer::StorageServer(const char* path, unsigned int flags,
                             kj::AsyncIoContext& aio_context)
    : aio_context_(aio_context),
      aio_(cas_internal::AsyncIOServer::Create(aio_context_)),
      aio_client_(aio_.first->GetMain<AsyncIO>()),
      dir_fd_(cas_internal::OpenFile(path, O_RDONLY | O_DIRECTORY)),
      index_fd_(cas_internal::OpenFile(dir_fd_.get(), "index",
                                       O_RDWR | O_CREAT | O_APPEND, 0666)),
      disable_read_(flags & kDisableRead) {
  for (size_t i = 0; i < 50; ++i) {
    std::string filename("data");
    if (i > 0) {
      filename.push_back('.');
      if (i < 10) filename.push_back('0');
      filename += std::to_string(i);
    }

    data_fds_.emplace_back(cas_internal::OpenFile(
        dir_fd_.get(), filename.c_str(), O_RDWR | O_CREAT | O_APPEND, 0666));

    off_t size;
    KJ_SYSCALL(size = lseek(data_fds_.back().get(), 0, SEEK_END));

    data_file_sizes_.emplace_back(size, i);
  }

  std::make_heap(data_file_sizes_.begin(), data_file_sizes_.end(),
                 HeapComparator);

  ReadIndex();

  try {
    auto config_file = cas_internal::OpenFile(dir_fd_.get(), "config",
                                              O_WRONLY | O_EXCL | O_CREAT);

    // Create the random buckets used for consistent hashing.  The number of
    // buckets is calculated from the storage capacity of the file system.
    struct statfs fs_stat;
    KJ_SYSCALL(fstatfs(dir_fd_.get(), &fs_stat));

    size_t bucket_count =
        (static_cast<size_t>(fs_stat.f_bsize) * fs_stat.f_blocks +
         kHashBucketSize - 1) /
        kHashBucketSize;
    KJ_REQUIRE(bucket_count > 0);

    static std::mt19937_64 strong_rng{std::random_device{}()};

    std::uniform_int_distribution<uint8_t> byte_distribution_;
    std::vector<CASKey> buckets(bucket_count);
    for (auto& bucket : buckets) {
      for (auto& b : bucket) b = byte_distribution_(strong_rng);
    }

    std::sort(buckets.begin(), buckets.end());

    capnp::MallocMessageBuilder message;
    auto config = message.initRoot<CAS::Config>();

    auto config_buckets = config.initBuckets(buckets.size());

    for (size_t i = 0; i < buckets.size(); ++i) {
      config_buckets.set(i,
                         kj::arrayPtr(buckets[i].begin(), buckets[i].size()));
    }

    capnp::writeMessageToFd(config_file.get(), message);
  } catch (kj::Exception e) {
    // If we get here, the config file probably already exists.  If we failed
    // for a different, we'll fail soon while attempting to read the
    // configuration file.
  }

  auto config_file = cas_internal::OpenFile(dir_fd_.get(), "config", O_RDONLY);

  config_data_ = cas_internal::ReadFile(config_file);
}

StorageServer::~StorageServer() {}

kj::Promise<void> StorageServer::get(CAS::Server::GetContext context) {
  KJ_REQUIRE(!disable_read_);

  CASKey sha1(context.getParams().getKey());

  size_t read_offset = context.getParams().getOffset();
  size_t read_size = context.getParams().getSize();

  auto i = index_.find(sha1);
  if (i != index_.end()) {
    const auto data_file_idx = (i->offset & kBucketMask) >> 56;
    const auto object_offset = i->offset & kOffsetMask;
    const auto object_size = i->size;

    if (marks_.erase(sha1)) garbage_size_ -= object_size;

    KJ_REQUIRE(read_offset <= object_size, read_offset, object_size);

    if (read_offset + read_size > object_size)
      read_size = object_size - read_offset;

    KJ_CONTEXT(object_offset, object_size);

    auto stream = context.getParams().getStream();

    auto expect_size_request = stream.expectSizeRequest();
    expect_size_request.setSize(read_size);
    expect_size_request.send().detach([](auto e) {});

    return WriteStream(std::move(stream), aio_client_,
                       data_fds_[data_file_idx].get(),
                       object_offset + read_offset, object_offset + read_size);
  }

  KJ_FAIL_REQUIRE("Object does not exist", sha1.ToString());
}

kj::Promise<void> StorageServer::beginGC(BeginGCContext context) {
  gc_id_ = std::max(gc_id_ + 1, cas_internal::CurrentTimeUSec());

  marks_.clear();
  garbage_size_ = 0;

  for (const auto& ie : index_) {
    marks_.emplace(ie.key);
    garbage_size_ += ie.size;
  }

  context.getResults().setId(gc_id_);

  return kj::READY_NOW;
}

kj::Promise<void> StorageServer::markGC(MarkGCContext context) {
  for (auto key_data : context.getParams().getKeys()) {
    CASKey key(key_data);

    if (marks_.erase(key)) {
      auto i = index_.find(key);
      KJ_REQUIRE(i != index_.end());
      garbage_size_ -= i->size;
    }
  }

  return kj::READY_NOW;
}

kj::Promise<void> StorageServer::endGC(EndGCContext context) {
  const auto gc_id = context.getParams().getId();
  KJ_REQUIRE(gc_id == gc_id_, "Conflicting garbage collection detected", gc_id,
             gc_id_);

  kj::FdOutputStream index_output(index_fd_.get());

  for (auto i = index_.begin(); i != index_.end();) {
    if (!marks_.count(i->key)) {
      ++i;
      continue;
    }

    const auto data_file_idx = (i->offset & kBucketMask) >> 56;
    data_file_utilization_[data_file_idx] -= i->size;

    IndexEntry ie;
    ie.offset = i->offset | kDeletedMask;
    ie.size = i->size;
    ie.key = i->key;

    i = index_.erase(i);

    index_output.write(&ie, sizeof(ie));
  }

  gc_id_ = 0;
  marks_ = std::unordered_set<CASKey>();
  garbage_size_ = 0;

  index_dirty_ = true;

  return kj::READY_NOW;
}

kj::Promise<void> StorageServer::put(CAS::Server::PutContext context) {
  auto key_data = context.getParams().getKey();
  KJ_REQUIRE(key_data.size() == 20, "Key size must be exactly 20 bytes");
  CASKey key(key_data.begin());

  auto i = index_.find(key);
  if (i != index_.end()) {
    // If we already have this object, use a null stream to discard the data
    // being written.
    //
    // TODO(mortehu): Handle the scenario where the already existing object was
    // written without the `sync flag, but the new object is written with the
    // `sync` flag.

    if (marks_.erase(key)) garbage_size_ -= i->size;

    context.getResults().setStream(kj::heap<NullStream>(*this));
    return kj::READY_NOW;
  }

  context.getResults().setStream(kj::heap<PutStream>(
      *this, context.getParams().getKey(), context.getParams().getSync()));
  return kj::READY_NOW;
}

kj::Promise<void> StorageServer::remove(CAS::Server::RemoveContext context) {
  auto key_data = context.getParams().getKey();
  KJ_REQUIRE(key_data.size() == 20, "Key size must be exactly 20 bytes");
  CASKey key(key_data.begin());

  auto i = index_.find(key);
  if (i != index_.end()) {
    const auto data_file_idx = (i->offset & kBucketMask) >> 56;
    data_file_utilization_[data_file_idx] -= i->size;

    if (marks_.erase(key)) garbage_size_ -= i->size;

    IndexEntry ie;
    ie.offset = i->offset | kDeletedMask;
    ie.size = i->size;
    ie.key = key;

    index_.erase(i);

    kj::FdOutputStream index_output(index_fd_.get());
    index_output.write(&ie, sizeof(ie));

    index_dirty_ = true;
  }

  return kj::READY_NOW;
}

kj::Promise<void> StorageServer::capacity(
    CAS::Server::CapacityContext context) {
  struct statfs data;
  KJ_SYSCALL(fstatfs(dir_fd_.get(), &data));
  context.getResults().setTotal(static_cast<uint64_t>(data.f_bsize) *
                                data.f_blocks);
  context.getResults().setAvailable(static_cast<uint64_t>(data.f_bsize) *
                                    data.f_bavail);

  const auto unreclaimed_space = GetUnreclaimedSpace();
  context.getResults().setUnreclaimed(std::accumulate(
      unreclaimed_space.begin(), unreclaimed_space.end(), size_t{}));

  context.getResults().setGarbage(garbage_size_);

  return kj::READY_NOW;
}

kj::Promise<void> StorageServer::list(CAS::Server::ListContext context) {
  KJ_REQUIRE(!disable_read_);

  const auto mode = context.getParams().getMode();
  const auto min_size = context.getParams().getMinSize();
  const auto max_size = context.getParams().getMaxSize();

  context.getResults().setList(
      kj::heap<ObjectListImpl>(this, mode, min_size, max_size));
  return kj::READY_NOW;
}

kj::Promise<void> StorageServer::compact(CompactContext context) {
  if (compacting_data_file_ >= 0) return kj::READY_NOW;

  const auto sync = context.getParams().getSync();

  const auto unreclaimed_space = GetUnreclaimedSpace();

  size_t max_unreclaimed_space = 0;
  size_t data_file_idx = 0;

  for (size_t i = 0; i < unreclaimed_space.size(); ++i) {
    if (unreclaimed_space[i] > max_unreclaimed_space) {
      max_unreclaimed_space = unreclaimed_space[i];
      data_file_idx = i;
    }
  }

  if (!max_unreclaimed_space) return CompactIndexFile(sync);

  compacting_data_file_ = data_file_idx;

  // After we've selected a data file to compact, remove it from the heap, so
  // that it won't be used by inserts happening while compaction is running.
  for (auto i = data_file_sizes_.begin();; ++i) {
    KJ_REQUIRE(i != data_file_sizes_.end());
    if (i->second == data_file_idx) {
      data_file_sizes_.erase(i);
      std::make_heap(data_file_sizes_.begin(), data_file_sizes_.end(),
                     HeapComparator);
      break;
    }
  }

  data_file_utilization_[data_file_idx] = 0;

  // TODO(mortehu): If any of these objects are removed by a separate RPC call
  // while it's still in this queue, we need to remove it from the queue.
  std::vector<IndexEntry> moves;
  size_t keep_prefix = 0;

  for (const auto& index_entry : index_) {
    if (data_file_idx != ((index_entry.offset & kBucketMask) >> 56)) continue;

    if ((index_entry.offset & kOffsetMask) == keep_prefix) {
      keep_prefix += index_entry.size;
      continue;
    }

    moves.emplace_back(index_entry);
  }

  // Reverse `moves` array so that we can use `pop_back` to remove each element
  // after processing.
  std::reverse(moves.begin(), moves.end());
  auto drain_promise = DrainDataFile(std::move(moves));

  if (sync) {
    drain_promise = drain_promise.then([this, data_file_idx] {
      // Make sure all moves are committed to disk before truncating the file
      // being drained.
      auto fsync_promises =
          kj::heapArrayBuilder<kj::Promise<void>>(data_fds_.size());

      for (size_t i = 0; i < data_fds_.size(); ++i) {
        if (i == data_file_idx) continue;
        fsync_promises.add(DataSync(data_fds_[i].get()));
      }

      fsync_promises.add(DataSync(index_fd_.get()));

      return kj::joinPromises(fsync_promises.finish());
    });
  }

  return drain_promise.then([this, keep_prefix, data_file_idx] {
    KJ_SYSCALL(ftruncate(data_fds_[data_file_idx].get(), keep_prefix));

    const auto dsz = std::make_pair(keep_prefix, data_file_idx);
    data_file_sizes_.emplace_back(dsz);
    std::push_heap(data_file_sizes_.begin(), data_file_sizes_.end(),
                   HeapComparator);

    data_file_utilization_[data_file_idx] = keep_prefix;

    compacting_data_file_ = -1;
  });
}

kj::Promise<void> StorageServer::getConfig(
    CAS::Server::GetConfigContext context) {
  capnp::FlatArrayMessageReader config_reader(
      kj::arrayPtr(reinterpret_cast<const capnp::word*>(config_data_.begin()),
                   config_data_.size() / sizeof(capnp::word)));
  context.getResults().setConfig(config_reader.getRoot<CAS::Config>());
  return kj::READY_NOW;
}

kj::Promise<void> StorageServer::Put(const CASKey& key, std::string data,
                                     bool sync) {
  if (index_.count(key)) return kj::READY_NOW;

  // Find the shortest data file.  This ensures all data files have
  // approximately the same length long term.
  std::pop_heap(data_file_sizes_.begin(), data_file_sizes_.end(),
                HeapComparator);
  const auto data_file_idx = data_file_sizes_.back().second;

  const auto data_fd = data_fds_[data_file_idx].get();

  off_t data_offset;
  KJ_SYSCALL(data_offset = lseek(data_fd, 0, SEEK_END));

  IndexEntry ie;
  ie.offset = data_offset | (data_file_idx << 56);
  ie.size = data.size();
  ie.key = key;

  kj::FdOutputStream data_output(data_fd);
  data_output.write(data.data(), data.size());

  data_file_sizes_.back().first += data.size();
  std::push_heap(data_file_sizes_.begin(), data_file_sizes_.end(),
                 HeapComparator);
  data_file_utilization_[data_file_idx] += data.size();

  // Writes are asynchronous as long as the writeback buffer isn't full, so
  // don't bother using AIO here.
  kj::FdOutputStream index_output(index_fd_.get());
  index_output.write(&ie, sizeof(ie));

  index_.emplace(ie);

  if (!sync) return kj::READY_NOW;

  auto fsync_promises = kj::heapArrayBuilder<kj::Promise<void>>(2);
  fsync_promises.add(DataSync(data_fd));
  fsync_promises.add(DataSync(index_fd_.get()));

  return kj::joinPromises(fsync_promises.finish());
}

kj::Promise<void> StorageServer::DataSync(int fd) {
  auto request = aio_client_.fsyncRequest();
  request.setFd(fd);
  return request.send().ignoreResult();
}

kj::Promise<void> StorageServer::CompactIndexFile(bool sync) {
  if (!index_dirty_) return kj::READY_NOW;

  // NOTE(mortehu): When using dir_fd_ instead of ".", glibc or Linux seems to
  // clear all the permission bits.
  auto new_index = cas_internal::AnonTemporaryFile(".", 0666);
  kj::FdOutputStream new_index_output{new_index.get()};

  std::vector<IndexEntry> buffer;

  for (const auto& index_entry : index_) {
    buffer.emplace_back(index_entry);

    if (buffer.size() == 65536) {
      new_index_output.write(buffer.data(), sizeof(buffer[0]) * buffer.size());
      buffer.clear();
    }
  }

  if (!buffer.empty())
    new_index_output.write(buffer.data(), sizeof(buffer[0]) * buffer.size());

  if (sync) {
    KJ_SYSCALL(fsync(new_index));
  }

  cas_internal::LinkAnonTemporaryFile(dir_fd_, new_index, "index");

  index_fd_ = std::move(new_index);
  index_dirty_ = false;

  return kj::READY_NOW;
}

kj::Promise<void> StorageServer::DrainDataFile(std::vector<IndexEntry> moves) {
  if (moves.empty()) return kj::READY_NOW;

  const auto move = moves.back();
  moves.pop_back();

  const auto data_file_idx = (move.offset & kBucketMask) >> 56;

  std::string data;
  data.resize(move.size);

  auto pread_request = aio_client_.preadRequest();
  pread_request.setFd(data_fds_[data_file_idx]);
  pread_request.setBuffer(reinterpret_cast<uint64_t>(data.data()));
  pread_request.setStart(move.offset & kOffsetMask);
  pread_request.setLength(move.size);

  return pread_request.send().then([
    this, move, moves = std::move(moves), data = std::move(data)
  ](auto pread_results) {
    auto index_entry = index_.find(move);
    KJ_REQUIRE(index_entry != index_.end());
    KJ_REQUIRE(index_entry->offset == move.offset);
    KJ_REQUIRE(index_entry->size == move.size);
    index_.erase(index_entry);
    return this->Put(move.key, std::move(data), false).then([
      this, moves = std::move(moves)
    ]() mutable { return this->DrainDataFile(std::move(moves)); });
  });
}

void StorageServer::ReadIndex() {
  off_t index_size;
  KJ_SYSCALL(index_size = lseek(index_fd_.get(), 0, SEEK_END));
  if (0 != (index_size % sizeof(IndexEntry))) {
    index_size = index_size / sizeof(IndexEntry) * sizeof(IndexEntry);
    KJ_SYSCALL(ftruncate(index_fd_.get(), index_size));
  }

  if (!index_size) return;

  size_t entry_count = index_size / sizeof(IndexEntry);
  index_.reserve(entry_count);

  std::array<IndexEntry, 1024> buffer;

  for (size_t i = 0; i < entry_count; i += buffer.size()) {
    auto count = std::min(buffer.size(), entry_count - i);

    cas_internal::ReadWithOffset(index_fd_.get(), &buffer[0],
                                 count * sizeof(IndexEntry),
                                 i * sizeof(IndexEntry));

    for (const auto& item :
         kj::arrayPtr(buffer.begin(), buffer.begin() + count)) {
      auto index_entry = index_.find(item);

      if (index_entry != index_.end()) {
        const auto data_file_idx = (index_entry->offset & kBucketMask) >> 56;
        data_file_utilization_[data_file_idx] -= index_entry->size;

        index_.erase(index_entry);
      }

      if (!(item.offset & kDeletedMask)) {
        const auto data_file_idx = (item.offset & kBucketMask) >> 56;
        data_file_utilization_[data_file_idx] += item.size;

        index_.emplace(item);
      } else {
        index_dirty_ = true;
      }
    }
  }
}

std::vector<size_t> StorageServer::GetUnreclaimedSpace() {
  std::vector<size_t> result;
  result.resize(data_fds_.size());

  for (const auto& dsz : data_file_sizes_) {
    result[dsz.second] = dsz.first - data_file_utilization_[dsz.second];
  }

  return result;
}

}  // namespace cas_internal
}  // namespace cantera
