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

#include <algorithm>
#include <climits>
#include <random>

#include "bytestream.h"
#include "client.h"
#include "io.h"
#include "sha1.h"
#include "storage-server.h"
#include "util.h"
#include "third_party/gtest/gtest.h"

using namespace cantera;

struct StorageServerTest : testing::Test {
 public:
  StorageServerTest() : async_io_{kj::setupAsyncIo()} {}

  ~StorageServerTest() noexcept {}

  void SetUp() override {
    temp_directory_ = TemporaryDirectory();

    Connect();
  }

  void TearDown() override {
    kj::Promise<void>(kj::READY_NOW).wait(async_io_.waitScope);

    cas_.reset();
    client_.reset();
    server_.reset();
  }

 protected:
  std::string TemporaryDirectory() {
    const char* tmpdir = getenv("TMPDIR");
    if (!tmpdir) tmpdir = "/tmp";

    char path[PATH_MAX];
    strcpy(path, tmpdir);
    strcat(path, "/test.XXXXXX");

    KJ_SYSCALL(mkdtemp(path));

    return path;
  }

  // Creates a client and a server object communicating over a Unix socket
  // pair.
  void Connect() {
    auto channel = async_io_.provider->newTwoWayPipe();

    server_ = std::make_unique<cas_internal::RPCServer<CAS>>(
        kj::heap<StorageServer>(temp_directory_.c_str(), 0, async_io_),
        std::move(channel.ends[0]));

    client_ =
        std::make_unique<cas_internal::RPCClient>(std::move(channel.ends[1]));

    cas_ = std::make_unique<CAS::Client>(client_->GetMain<CAS>());
  }

  kj::Array<const capnp::byte> RandomData() {
    std::uniform_int_distribution<capnp::byte> byte_distribution;
    std::uniform_int_distribution<size_t> size_distribution(1, 10000);

    auto length = size_distribution(rng_);
    auto result = kj::heapArray<capnp::byte>(length);

    for (auto& b : result) b = byte_distribution(rng_);

    return std::move(result);
  }

  CASKey PutObject(kj::Array<const capnp::byte> data) {
    CASKey data_sha1_digest;
    cas_internal::SHA1::Digest(data.begin(), data.size(),
                               data_sha1_digest.begin());

    auto put_request = cas_->putRequest();
    put_request.setKey(kj::arrayPtr<capnp::byte>(data_sha1_digest.begin(), 20));
    put_request.setSync(false);
    auto stream = put_request.send().getStream();

    auto write_request = stream.writeRequest();
    write_request.setData(std::move(data));
    auto write_response = write_request.send().wait(async_io_.waitScope);

    stream.doneRequest().send().wait(async_io_.waitScope);

    return data_sha1_digest;
  }

  CASKey PutRandomObject() { return PutObject(RandomData()); }

  kj::AsyncIoContext async_io_;

  std::default_random_engine rng_;

  std::string temp_directory_;

  std::unique_ptr<cas_internal::RPCServer<CAS>> server_;
  std::unique_ptr<cas_internal::RPCClient> client_;
  std::unique_ptr<CAS::Client> cas_;
};

// Verifies that we can put and get an object, and that the SHA1 calculation is
// consistent.
TEST_F(StorageServerTest, PutAndGet) {
  auto data = RandomData();
  auto data_sha1_digest = PutObject(kj::heapArray<const capnp::byte>(data));

  auto read_data = std::make_shared<kj::Array<char>>();
  auto read_stream = kj::heap<ByteStreamCollector>(read_data);

  auto get_request = cas_->getRequest();
  get_request.setKey(
      kj::arrayPtr(data_sha1_digest.begin(), data_sha1_digest.end()));
  get_request.setStream(std::move(read_stream));
  get_request.send().wait(async_io_.waitScope);

  ASSERT_TRUE(read_data != nullptr);

  EXPECT_EQ(data.size(), read_data->size());
  EXPECT_TRUE(std::equal(data.begin(), data.end(), read_data->begin(),
                         read_data->end()));
}

// Verifies that file objects persist across server restarts.
TEST_F(StorageServerTest, PutAndGetAcrossSessions) {
  auto data = RandomData();
  auto data_sha1_digest = PutObject(kj::heapArray<const capnp::byte>(data));

  Connect();

  std::string read_data;

  auto get_request = cas_->getRequest();
  get_request.setKey(
      kj::arrayPtr(data_sha1_digest.begin(), data_sha1_digest.end()));
  get_request.setStream(kj::heap<ByteStreamCollector>(read_data));
  get_request.send().wait(async_io_.waitScope);

  ASSERT_EQ(data.size(), read_data.size());
  EXPECT_EQ(std::string(data.begin(), data.end()), read_data);
}

// Verifies that removing a file object causes subsequent get requests to fail.
TEST_F(StorageServerTest, RemovedFileStaysRemoved) {
  auto data_sha1_digest = PutRandomObject();

  auto remove_request = cas_->removeRequest();
  remove_request.setKey(
      kj::arrayPtr(data_sha1_digest.begin(), data_sha1_digest.end()));
  remove_request.send().wait(async_io_.waitScope);

  auto get_request = cas_->getRequest();
  get_request.setKey(
      kj::arrayPtr(data_sha1_digest.begin(), data_sha1_digest.end()));
  ASSERT_THROW(get_request.send().wait(async_io_.waitScope), kj::Exception);
}

// Verifies the basic sanity of the hash buckets, and that they remain the same
// across server restarts.
TEST_F(StorageServerTest, PersistentHashBuckets) {
  std::vector<CASKey> buckets;

  {
    auto config = cas_->getConfigRequest().send().wait(async_io_.waitScope);

    for (auto config_bucket : config.getConfig().getBuckets()) {
      ASSERT_EQ(20U, config_bucket.size());
      CASKey bucket;
      std::copy(config_bucket.begin(), config_bucket.end(), bucket.begin());
      buckets.emplace_back(std::move(bucket));
    }

    // May break if the temporary file system capacity is less than 128 MB.
    EXPECT_LT(1U, buckets.size());

    EXPECT_TRUE(std::is_sorted(buckets.begin(), buckets.end()));
    EXPECT_EQ(buckets.end(), std::unique(buckets.begin(), buckets.end()));
  }

  Connect();

  {
    auto config = cas_->getConfigRequest().send().wait(async_io_.waitScope);

    std::vector<CASKey> new_buckets;
    for (auto config_bucket : config.getConfig().getBuckets()) {
      ASSERT_EQ(20U, config_bucket.size());
      CASKey bucket;
      std::copy(config_bucket.begin(), config_bucket.end(), bucket.begin());
      new_buckets.emplace_back(std::move(bucket));
    }

    ASSERT_EQ(buckets.size(), new_buckets.size());
    EXPECT_TRUE(std::equal(buckets.begin(), buckets.end(), new_buckets.begin(),
                           new_buckets.end()));
  }
}

// Verifies that the list operation returns all inserted objects.
TEST_F(StorageServerTest, PutThenList) {
  static const size_t kObjectCount = 15;

  auto promises = kj::heapArrayBuilder<kj::Promise<CASKey>>(kObjectCount);

  for (size_t i = 0; i < kObjectCount; ++i) {
    auto data = RandomData();

    CASKey data_sha1_digest;
    cas_internal::SHA1::Digest(data.begin(), data.size(),
                               data_sha1_digest.begin());

    auto put_request = cas_->putRequest();
    put_request.setKey(kj::arrayPtr<capnp::byte>(data_sha1_digest.begin(), 20));

    auto stream = kj::heap<ByteStreamProducer>(put_request.send().getStream());

    stream->Write(std::move(data));

    promises.add(
        stream->Done().attach(std::move(stream)).then([data_sha1_digest] {
          return data_sha1_digest;
        }));
  }

  std::vector<CASKey> keys;
  for (const auto& key :
       kj::joinPromises(promises.finish()).wait(async_io_.waitScope))
    keys.emplace_back(key);

  {
    auto list_request = cas_->listRequest();
    auto object_list = list_request.send().getList();
    auto object_list_result =
        object_list.readRequest().send().wait(async_io_.waitScope);
    auto objects = object_list_result.getObjects();

    ASSERT_EQ(kObjectCount, objects.size());

    std::vector<CASKey> list_keys;

    for (auto object : objects) {
      ASSERT_EQ(20U, object.size());
      list_keys.emplace_back(object.begin());
    }

    std::sort(keys.begin(), keys.end());
    std::sort(list_keys.begin(), list_keys.end());
    EXPECT_EQ(keys, list_keys);
  }

  // Check for empty result when we set a too high minimum size.
  {
    auto list_request = cas_->listRequest();
    list_request.setMinSize(10000000);
    auto object_list = list_request.send().getList();
    auto object_list_result =
        object_list.readRequest().send().wait(async_io_.waitScope);
    auto objects = object_list_result.getObjects();

    EXPECT_EQ(0U, objects.size());
  }
}

// Verifies the basic behavior of the garbage collector.
TEST_F(StorageServerTest, GarbageCollector) {
  auto data0_key = PutObject(RandomData());

  auto data1_key = PutObject(RandomData());

  // Verify that neither item is currently marked as garbage.
  {
    std::vector<CASKey> garbage_keys;
    CASClient::ListAsync(
        *cas_,
        [&garbage_keys](const CASKey& key) { garbage_keys.emplace_back(key); },
        CAS::ListMode::GARBAGE)
        .wait(async_io_.waitScope);
    EXPECT_EQ(0U, garbage_keys.size());
  }

  auto gcid0 = CASClient::BeginGC(*cas_).wait(async_io_.waitScope);
  auto gcid1 = CASClient::BeginGC(*cas_).wait(async_io_.waitScope);
  EXPECT_NE(gcid0, gcid1);

  // Keep `data0`.
  std::vector<CASKey> gc_keys;
  gc_keys.emplace_back(data0_key);
  CASClient::MarkGC(*cas_, gc_keys).wait(async_io_.waitScope);

  // Verify that `data1` is now marked as garbage.
  {
    std::vector<CASKey> garbage_keys;
    CASClient::ListAsync(
        *cas_,
        [&garbage_keys](const CASKey& key) { garbage_keys.emplace_back(key); },
        CAS::ListMode::GARBAGE)
        .wait(async_io_.waitScope);
    ASSERT_EQ(1U, garbage_keys.size());
    EXPECT_EQ(garbage_keys[0], data1_key);
  }

  // Verify that ending the interrupted GC results in an exception.
  ASSERT_THROW(CASClient::EndGC(*cas_, gcid0).wait(async_io_.waitScope),
               kj::Exception);

  // Verify that both the original keys are still available.
  {
    std::vector<CASKey> all_keys;
    CASClient::ListAsync(*cas_, [&all_keys](const CASKey& key) {
      all_keys.emplace_back(key);
    }).wait(async_io_.waitScope);
    EXPECT_EQ(2U, all_keys.size());
  }

  CASClient::EndGC(*cas_, gcid1).wait(async_io_.waitScope);

  // Verify that (only) the garbage object was removed.
  {
    std::vector<CASKey> all_keys;
    CASClient::ListAsync(*cas_, [&all_keys](const CASKey& key) {
      all_keys.emplace_back(key);
    }).wait(async_io_.waitScope);
    ASSERT_EQ(1U, all_keys.size());
    EXPECT_EQ(all_keys[0], data0_key);
  }
}

// Verifies that compaction doesn't corrupt the repository.
TEST_F(StorageServerTest, Compaction) {
  static const size_t kMaxIterations = 500;

  std::vector<CASKey> objects;

  for (size_t i = 0; i < kMaxIterations; ++i) {
    const auto new_object_key = PutRandomObject();
    auto insertion_point =
        std::lower_bound(objects.begin(), objects.end(), new_object_key);
    objects.insert(insertion_point, new_object_key);

    if (i > 200) {
      std::uniform_int_distribution<size_t> dist(0, objects.size() - 1);
      const auto j = dist(rng_);

      CASClient::RemoveAsync(*cas_, objects[j]).wait(async_io_.waitScope);
      CASClient::CompactAsync(*cas_, false).wait(async_io_.waitScope);
      objects.erase(objects.begin() + j);

      // Verify that the objects known by the server are the same ones we hav
      std::set<CASKey> remote_objects;
      CASClient::ListAsync(*cas_, [&remote_objects](const CASKey& key) {
        remote_objects.emplace(key);
      }).wait(async_io_.waitScope);

      ASSERT_EQ(objects.size(), remote_objects.size());

      size_t k = 0;
      for (const auto& remote_key : remote_objects)
        ASSERT_EQ(objects[k++], remote_key);
    }
  }
}
