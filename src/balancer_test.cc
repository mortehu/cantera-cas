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

#include "balancer.h"
#include "bytestream.h"
#include "client.h"
#include "sha1.h"
#include "storage-server.h"
#include "third_party/gtest/gtest.h"

using namespace cantera;
using namespace cantera::cas_internal;

struct RpcBalancerTest : testing::Test {
 public:
  RpcBalancerTest() : async_io_{kj::setupAsyncIo()} {}

  ~RpcBalancerTest() noexcept {}

  // Starts several storage backends using temporary directories, and then
  // starts a balancer server working across them.
  void SetUp() override {
    auto balancer_channel = async_io_.provider->newTwoWayPipe();

    auto balancer_server = kj::heap<BalancerServer>(async_io_);
    balancer_server_ = balancer_server.get();

    balancer_ = std::make_unique<RPCServer<CAS>>(
        std::move(balancer_server), std::move(balancer_channel.ends[0]));

    client_ = std::make_unique<RPCClient>(std::move(balancer_channel.ends[1]));

    cas_ = std::make_unique<CAS::Client>(client_->GetMain<CAS>());
  }

  void TearDown() override {
    kj::Promise<void>(kj::READY_NOW).wait(async_io_.waitScope);

    storage_servers_.clear();

    cas_.reset();
    client_.reset();
    balancer_.reset();
  }

  void AddBackend(kj::WaitScope& wait_scope, uint8_t failure_domain = 0) {
    auto backend_channel = async_io_.provider->newTwoWayPipe();

    auto repo_root = TemporaryDirectory();

    storage_servers_.emplace_back(std::make_unique<RPCServer<CAS>>(
        kj::heap<StorageServer>(repo_root.c_str(), 0, async_io_),
        std::move(backend_channel.ends[0])));

    auto client = std::make_shared<CASClient>(
        std::move(backend_channel.ends[1]), async_io_);

    balancer_server_->AddBackend(std::move(client), failure_domain);
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

  kj::Array<const capnp::byte> RandomData() {
    auto result = kj::heapArray<capnp::byte>(512);

    for (auto& b : result) b = byte_distribution_(rng_);

    return std::move(result);
  }

  CASKey PutObject(kj::Array<const capnp::byte> data) {
    CASKey data_sha1_digest;
    SHA1::Digest(data.begin(), data.size(), data_sha1_digest.begin());

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

  std::default_random_engine rng_;
  std::uniform_int_distribution<capnp::byte> byte_distribution_;

  kj::AsyncIoContext async_io_;

  std::vector<std::unique_ptr<RPCServer<CAS>>> storage_servers_;

  BalancerServer* balancer_server_ = nullptr;
  std::unique_ptr<RPCServer<CAS>> balancer_;
  std::unique_ptr<RPCClient> client_;
  std::unique_ptr<CAS::Client> cas_;
};

// Verifies that the list operation returns all inserted objects.
TEST_F(RpcBalancerTest, PutThenList) {
  static const size_t kObjectCount = 30;

  AddBackend(async_io_.waitScope);
  AddBackend(async_io_.waitScope);
  AddBackend(async_io_.waitScope);

  std::vector<CASKey> keys;

  for (size_t i = 0; i < kObjectCount; ++i) {
    auto data = RandomData();

    CASKey data_sha1_digest;
    SHA1::Digest(data.begin(), data.size(), data_sha1_digest.begin());

    keys.emplace_back(data_sha1_digest);

    auto put_request = cas_->putRequest();
    put_request.setSync(false);
    put_request.setKey(kj::arrayPtr<capnp::byte>(data_sha1_digest.begin(), 20));

    auto stream = kj::heap<ByteStreamProducer>(put_request.send().getStream());

    stream->Write(std::move(data));
    stream->Done().attach(std::move(stream)).wait(async_io_.waitScope);
  }

  {
    auto object_list = cas_->listRequest().send().getList();
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

TEST_F(RpcBalancerTest, CapacityResponseIsSane) {
  AddBackend(async_io_.waitScope);
  auto request = cas_->capacityRequest();
  auto response = request.send().wait(async_io_.waitScope);
  EXPECT_GT(response.getTotal(), 0U);
  EXPECT_LE(response.getAvailable(), response.getTotal());
}

// Verifies that we can put and get an object, and that the SHA1 calculation is
// consistent.
TEST_F(RpcBalancerTest, SimplePutAndGet) {
  AddBackend(async_io_.waitScope);

  auto data = RandomData();
  CASKey data_sha1_digest;
  SHA1::Digest(data.begin(), data.size(), data_sha1_digest.begin());

  auto put_request = cas_->putRequest();
  put_request.setKey(kj::arrayPtr<capnp::byte>(data_sha1_digest.begin(), 20));

  auto stream = kj::heap<ByteStreamProducer>(put_request.send().getStream());

  stream->Write(data.begin(), data.size());
  stream->Done().wait(async_io_.waitScope);

  std::string read_data;
  auto read_stream = kj::heap<ByteStreamCollector>(read_data);

  auto get_request = cas_->getRequest();
  get_request.setKey(kj::arrayPtr<capnp::byte>(data_sha1_digest.begin(), 20));
  get_request.setStream(std::move(read_stream));
  get_request.send().wait(async_io_.waitScope);

  ASSERT_EQ(data.size(), read_data.size());
  EXPECT_TRUE(std::equal(data.begin(), data.end(), read_data.begin(),
                         read_data.end(), [](const auto lhs, const auto rhs) {
                           return static_cast<uint8_t>(lhs) ==
                                  static_cast<uint8_t>(rhs);
                         }));
}

// Verifies that the server will refuse to accept objects whose SHA-1 digest
// does not match the key set by the client.
TEST_F(RpcBalancerTest, PutWithWrongKeyThrows) {
  AddBackend(async_io_.waitScope);

  auto data = RandomData();
  CASKey data_sha1_digest;
  SHA1::Digest(data.begin(), data.size(), data_sha1_digest.begin());

  // We generate new random data, so that the SHA-1 digests calculated here and
  // on the storage server won't match.
  data = RandomData();

  auto put_request = cas_->putRequest();
  put_request.setKey(kj::arrayPtr<capnp::byte>(data_sha1_digest.begin(), 20));

  auto stream = kj::heap<ByteStreamProducer>(put_request.send().getStream());

  stream->Write(std::move(data));
  ASSERT_THROW(stream->Done().wait(async_io_.waitScope), kj::Exception);
}

// Verifies that the balancer does not accept writes when there are no
// viable backends.
TEST_F(RpcBalancerTest, PutToEmptyBackendThrows) {
  CASKey dummy_key;

  auto put_request = cas_->putRequest();
  put_request.setKey(kj::arrayPtr<capnp::byte>(dummy_key.begin(), 20));

  ASSERT_THROW(put_request.send().wait(async_io_.waitScope), kj::Exception);
}

// Verify that we can put and get to sharded backends.
TEST_F(RpcBalancerTest, PutAndGetSharded) {
  for (size_t replicas = 1; replicas <= 3; ++replicas) {
    balancer_server_->SetReplicas(replicas);

    // Verify that insertion fails when the replica count is higher than the
    // number of unique failure domains.
    CASKey fake_key;
    std::fill(fake_key.begin(), fake_key.end(), 0xce);

    auto put_request = cas_->putRequest();
    put_request.setSync(false);
    put_request.setKey(kj::arrayPtr<capnp::byte>(fake_key.begin(), 20));

    ASSERT_THROW(put_request.send().wait(async_io_.waitScope), kj::Exception);

    // Make another failure domain.
    AddBackend(async_io_.waitScope, replicas - 1);

    static const size_t kObjectCount = 5;

    std::vector<CASKey> keys;

    for (size_t i = 0; i < kObjectCount; ++i) {
      auto data = RandomData();

      CASKey data_sha1_digest;
      SHA1::Digest(data.begin(), data.size(), data_sha1_digest.begin());
      keys.emplace_back(data_sha1_digest.begin());

      auto put_request = cas_->putRequest();
      put_request.setSync(false);
      put_request.setKey(
          kj::arrayPtr<capnp::byte>(data_sha1_digest.begin(), 20));

      auto stream =
          kj::heap<ByteStreamProducer>(put_request.send().getStream());

      stream->Write(std::move(data));
      stream->Done().wait(async_io_.waitScope);
    }

    for (const auto& key : keys) {
      std::string read_data;
      auto read_stream = kj::heap<ByteStreamCollector>(read_data);

      auto get_request = cas_->getRequest();
      get_request.setKey(kj::arrayPtr(key.begin(), key.end()));
      get_request.setStream(std::move(read_stream));
      get_request.send().wait(async_io_.waitScope);

      EXPECT_FALSE(read_data.empty());
    }
  }
}

// Verify that we can put and get to sharded backends.
TEST_F(RpcBalancerTest, GetConfig) {
  AddBackend(async_io_.waitScope);
  AddBackend(async_io_.waitScope);
  AddBackend(async_io_.waitScope);

  auto req = cas_->getConfigRequest();

  auto result = req.send().wait(async_io_.waitScope);

  EXPECT_LT(3U, result.getConfig().getBuckets().size());
}

// Verifies the basic behavior of the garbage collector.
TEST_F(RpcBalancerTest, GarbageCollector) {
  AddBackend(async_io_.waitScope, 0);
  AddBackend(async_io_.waitScope, 1);
  AddBackend(async_io_.waitScope, 2);
  balancer_server_->SetReplicas(2);

  auto data0_key = PutObject(RandomData());
  auto data1_key = PutObject(RandomData());

  // Verify that neither item is currently marked as garbage.
  {
    std::unordered_set<CASKey> garbage_keys;
    CASClient::ListAsync(
        *cas_,
        [&garbage_keys](const CASKey& key) { garbage_keys.emplace(key); },
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
    std::unordered_set<CASKey> garbage_keys;
    CASClient::ListAsync(
        *cas_,
        [&garbage_keys](const CASKey& key) { garbage_keys.emplace(key); },
        CAS::ListMode::GARBAGE)
        .wait(async_io_.waitScope);
    ASSERT_EQ(1U, garbage_keys.size());
    EXPECT_EQ(*garbage_keys.begin(), data1_key);
  }

  // Verify that ending the interrupted GC results in an exception.
  ASSERT_THROW(CASClient::EndGC(*cas_, gcid0).wait(async_io_.waitScope),
               kj::Exception);

  // Verify that both the original keys are still available, with 2 replicas.
  {
    std::unordered_set<CASKey> all_keys;
    size_t dupes = 0;
    CASClient::ListAsync(*cas_, [&all_keys, &dupes](const CASKey& key) {
      if (!all_keys.emplace(key).second) ++dupes;
    }).wait(async_io_.waitScope);
    EXPECT_EQ(2U, dupes);
    EXPECT_EQ(2U, all_keys.size());
  }

  CASClient::EndGC(*cas_, gcid1).wait(async_io_.waitScope);

  // Verify that (only) the garbage object was removed.
  {
    std::unordered_set<CASKey> all_keys;
    CASClient::ListAsync(*cas_, [&all_keys](const CASKey& key) {
      all_keys.emplace(key);
    }).wait(async_io_.waitScope);
    ASSERT_EQ(1U, all_keys.size());
    EXPECT_EQ(*all_keys.begin(), data0_key);
  }
}
