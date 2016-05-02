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
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <functional>
#include <limits>
#include <unordered_map>

#include <err.h>
#include <fcntl.h>
#include <getopt.h>
#include <glob.h>
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sysexits.h>
#include <unistd.h>

#include <capnp/ez-rpc.h>
#include <columnfile.h>
#include <kj/array.h>
#include <kj/debug.h>

#include "client.h"
#include "io.h"
#include "progress.h"
#include "proto/ca-cas.capnp.h"
#include "sharding.h"
#include "storage-server.h"
#include "util.h"

using namespace cantera;

namespace {

int print_help;
int print_version;
int no_remove;
CAS::ListMode list_mode = CAS::ListMode::DEFAULT;
uint64_t min_size;
uint64_t max_size = std::numeric_limits<uint64_t>::max();
cantera::ColumnFileCompression compression =
    cantera::kColumnFileCompressionDefault;
std::vector<std::string> exclude_paths;

std::unique_ptr<kj::AsyncIoContext> aio_context;

enum Option : int {
  kOptionCompression = 'c',
  kOptionExclude = 'e',
  kOptionListMode = 'L',
  kOptionMaxSize = 'M',
  kOptionMinSize = 'm',
  kOptionServerAddress = 's',
};

struct option kLongOptions[] = {
    {"compression", required_argument, nullptr, kOptionCompression},
    {"exclude", required_argument, nullptr, kOptionExclude},
    {"list-mode", required_argument, nullptr, kOptionListMode},
    {"max-size", required_argument, nullptr, kOptionMaxSize},
    {"min-size", required_argument, nullptr, kOptionMinSize},
    {"no-remove", no_argument, &no_remove, 1},
    {"server", required_argument, nullptr, kOptionServerAddress},
    {"version", no_argument, &print_version, 1},
    {"help", no_argument, &print_help, 1},
    {nullptr, 0, nullptr, 0}};

// Helper class for processing a list of move operations with a high level of
// concurrency.
class MoveQueue {
 public:
  // Adds a move operation to the queue.
  void Add(const CASKey& key, CASClient* from, CASClient* to) {
    moves_[from].emplace_back(key, to);
    ++move_count_;
  }

  void RunQueue(size_t max_concurrency) {
    const auto concurrency = std::min(max_concurrency, move_count_);
    progress_ = std::make_unique<cas_internal::Progress>(move_count_, "moves");

    auto promises = kj::Vector<kj::Promise<void>>(concurrency);

    next_queue_ = moves_.begin();
    for (size_t i = 0; i < concurrency; ++i) promises.add(Process());

    kj::joinPromises(promises.releaseAsArray()).wait(aio_context->waitScope);

    progress_.reset();
  }

  size_t size() const { return move_count_; }

 private:
  kj::Promise<void> Process() {
    if (!move_count_) return kj::READY_NOW;

    while (next_queue_->second.empty()) {
      next_queue_ = moves_.erase(next_queue_);
      if (next_queue_ == moves_.end()) {
        next_queue_ = moves_.begin();
        KJ_ASSERT(next_queue_ != moves_.end());
      }
    }

    auto move = std::move(next_queue_->second.front());
    next_queue_->second.pop_front();
    --move_count_;

    auto source = next_queue_->first;
    if (++next_queue_ == moves_.end()) next_queue_ = moves_.begin();

    auto target = std::get<CASClient*>(move);

    const auto& key = std::get<CASKey>(move);

    auto get_request = source->GetStream(key.ToHex(),
                                         target->PutStream(key, false));

    return get_request.then([this] {
      if (progress_) progress_->Put(1);
      return this->Process();
    });
  }

  typedef std::unordered_map<CASClient*,
                             std::deque<std::tuple<CASKey, CASClient*>>>
      MoveMap;

  MoveMap moves_;
  size_t move_count_ = 0;

  MoveMap::iterator next_queue_;
  std::unique_ptr<cas_internal::Progress> progress_;
};

class RemovalQueue {
 public:
  // Adds a move operation to the queue.
  void Add(const CASKey& key, CASClient* from) {
    removals_[from].emplace_back(key);
    ++removal_count_;
  }

  void RunQueue(size_t max_concurrency) {
    const auto concurrency = std::min(max_concurrency, removal_count_);
    progress_ =
        std::make_unique<cas_internal::Progress>(removal_count_, "removals");

    auto promises = kj::Vector<kj::Promise<void>>(concurrency);

    next_queue_ = removals_.begin();
    for (size_t i = 0; i < concurrency; ++i) promises.add(Process());

    kj::joinPromises(promises.releaseAsArray()).wait(aio_context->waitScope);
  }

  size_t size() const { return removal_count_; }

 private:
  kj::Promise<void> Process() {
    if (!removal_count_) return kj::READY_NOW;

    while (next_queue_->second.empty()) {
      next_queue_ = removals_.erase(next_queue_);
      if (next_queue_ == removals_.end()) {
        next_queue_ = removals_.begin();
        KJ_ASSERT(next_queue_ != removals_.end());
      }
    }

    auto key = std::move(next_queue_->second.front());
    next_queue_->second.pop_front();
    --removal_count_;

    auto source = next_queue_->first;
    if (++next_queue_ == removals_.end()) next_queue_ = removals_.begin();

    auto remove_request = source->RemoveAsync(key);

    return remove_request.then([this] {
      if (progress_) progress_->Put(1);
      return this->Process();
    });
  }

  typedef std::unordered_map<CASClient*, std::deque<CASKey>> RemovalMap;

  RemovalMap removals_;
  size_t removal_count_ = 0;

  RemovalMap::iterator next_queue_;
  std::unique_ptr<cas_internal::Progress> progress_;
};

class ExportQueue {
 public:
  ExportQueue(CASClient* client, std::vector<CASKey> objects)
      : client_(client),
        objects_(std::move(objects)),
        progress_(objects_.size(), "objects"),
        output_(kj::AutoCloseFd(STDOUT_FILENO)) {
    output_.SetCompression(compression);
  }

  void RunQueue(size_t max_concurrency) {
    const auto concurrency = std::min(max_concurrency, objects_.size());

    auto promises = kj::Vector<kj::Promise<void>>(concurrency);

    for (size_t i = 0; i < concurrency; ++i) promises.add(Process());

    kj::joinPromises(promises.releaseAsArray()).wait(aio_context->waitScope);
  }

  ~ExportQueue() {
    if (objects_.empty()) output_.Finalize();
  }

 private:
  kj::Promise<void> Process() {
    if (objects_.empty()) return kj::READY_NOW;

    const auto key = objects_.back();
    objects_.pop_back();

    const auto hex_key = key.ToHex();

    auto get_request = client_->GetAsync(hex_key);

    return get_request.then([this, key](auto data) {
      static const auto kFlushIntervalBytes = UINT64_C(64)
                                              << 20;  // 64 megabytes.

      std::vector<std::pair<uint32_t, cantera::optional_string_view>> row;
      row.reserve(2);
      row.emplace_back(
          0, cantera::string_view{reinterpret_cast<const char*>(key.data()),
                                  key.size()});
      row.emplace_back(1, cantera::string_view{data.begin(), data.size()});

      output_.PutRow(row);

      if (output_.PendingSize() >= kFlushIntervalBytes) output_.Flush();

      progress_.Put(1);
      return this->Process();
    });
  }

  CASClient* client_;

  std::vector<CASKey> objects_;

  cas_internal::Progress progress_;

  cantera::ColumnFileWriter output_;
};

bool Get(CASClient* client, char** argv, int argc) {
  if (argc < 1) {
    errx(EX_USAGE, "The 'get' command takes at least 1 argument, %d given",
         argc);
  }

  bool has_error = false;

  for (int i = 0; i < argc; ++i) {
    try {
      kj::FdOutputStream output(STDOUT_FILENO);
      const auto data = client->Get(argv[i]);
      output.write(data.begin(), data.size());
    } catch (kj::Exception e) {
      auto desc = e.getDescription();
      fprintf(stderr, "Error retrieving %s: %s\n", argv[i], desc.cStr());
      has_error = true;
    }
  }

  return !has_error;
}

bool BeginGC(CASClient* client, char** argv, int argc) {
  if (argc != 0)
    errx(EX_USAGE, "The 'begin-gc' command doest not take any arguments");
  const auto id = client->BeginGC().wait(aio_context->waitScope);

  printf("%" PRIu64 "\n", id);

  return true;
}

bool MarkGC(CASClient* client, char** argv, int argc) {
  client->OnConnect().wait(aio_context->waitScope);

  std::vector<CASKey> keys;

  for (int i = 0; i < argc; ++i)
    keys.emplace_back(CASKey::FromString(argv[i]));

  client->MarkGC(keys).wait(aio_context->waitScope);

  return true;
}

bool EndGC(CASClient* client, char** argv, int argc) {
  if (argc != 1) {
    errx(EX_USAGE, "The 'end-gc' command takes exactly 1 argument, %d given",
         argc);
  }

  const auto id = cas_internal::StringToUInt64(argv[0]);
  client->EndGC(id).wait(aio_context->waitScope);

  return true;
}

bool Ping(CASClient* client, char** argv, int argc) {
  if (argc != 0)
    errx(EX_USAGE, "The 'ping' command doest not take any arguments");

  client->OnConnect().wait(aio_context->waitScope);

  return true;
}

bool Put(CASClient* client, char** argv, int argc) {
  if (argc == 0) {
    const auto key = client->Put(cas_internal::ReadFile(STDIN_FILENO));
    printf("%s\n", key.c_str());
  } else {
    for (int i = 0; i < argc; ++i) {
      const auto key = client->Put(
          cas_internal::ReadFile(cas_internal::OpenFile(argv[i], O_RDONLY)));
      printf("%s\n", key.c_str());
    }
  }

  return true;
}

bool List(CASClient* client, char** argv, int argc) {
  if (argc != 0) {
    errx(EX_USAGE, "The 'list' command takes exactly 0 arguments, %d given",
         argc);
  }

  std::string hex;
  hex.reserve(40);

  client
      ->ListAsync(
          [&hex](const CASKey& key) {
            hex.clear();
            cas_internal::BinaryToHex(key.begin(), key.size(), &hex);
            printf("%s\n", hex.c_str());
          },
          list_mode, min_size, max_size)
      .wait(aio_context->waitScope);

  return true;
}

bool Remove(CASClient* client, char** argv, int argc) {
  if (argc < 1)
    errx(EX_USAGE, "The 'rm' command takes at least 1 argument, %d given",
         argc);

  for (int i = 0; i < argc; ++i)
    client->Remove(CASKey::FromString(argv[i]));

  return true;
}

bool Capacity(CASClient* client, char** argv, int argc) {
  if (argc != 0) {
    errx(EX_USAGE, "The 'capacity' command takes exactly 0 arguments, %d given",
         argc);
  }

  auto request = client->RawClient().capacityRequest();
  auto response = request.send().wait(client->WaitScope());

  printf("total       %" PRIu64
         "\n"
         "available   %" PRIu64
         "\n"
         "unreclaimed %" PRIu64
         "\n"
         "garbage     %" PRIu64 "\n",
         response.getTotal(), response.getAvailable(),
         response.getUnreclaimed(), response.getGarbage());

  return true;
}

bool Compact(CASClient* client, char** argv, int argc) {
  if (argc != 0) {
    errx(EX_USAGE, "The 'compact' command takes exactly 0 arguments, %d given",
         argc);
  }

  client->CompactAsync().wait(aio_context->waitScope);

  return true;
}

void Balance(char** argv, int argc) {
  if (argc != 1) {
    err(EX_USAGE, "The 'balance' command takes at exactly 1 argument, %d given",
        argc);
  }

  ShardingInfo sharding_info(argv[0], *aio_context);

  const auto& backends = sharding_info.Backends();

  fprintf(stderr, "Got %zu buckets in %zu backends\n",
          sharding_info.BucketCount(), backends.size());

  std::vector<std::pair<CASKey, CASClient*>> object_presence;

  {
    cas_internal::Progress progress(backends.size(), "backends");

    auto promises = kj::Vector<kj::Promise<void>>(backends.size());

    for (const auto& backend : backends) {
      auto client = backend.client.get();

      promises.add(backend.client
                       ->ListAsync(
                           [&object_presence, client](const CASKey& key) {
                             object_presence.emplace_back(key, client);
                           },
                           CAS::ListMode::DEFAULT, min_size, max_size)
                       .then([&progress] { progress.Put(1); }));
    }

    kj::joinPromises(promises.releaseAsArray()).wait(aio_context->waitScope);
  }

  std::sort(object_presence.begin(), object_presence.end());

  MoveQueue moves;
  std::vector<CASClient*> key_backends;
  size_t unique_objects = 0;

  RemovalQueue removals;

  {
    cas_internal::Progress progress(object_presence.size(), "objects");

    std::mt19937_64 rng;

    for (auto i = object_presence.begin(); i != object_presence.end();
         ++unique_objects) {
      auto j = i;
      ++j;

      while (j != object_presence.end() && j->first == i->first) ++j;

      key_backends.clear();
      sharding_info.GetWriteBackendsForKey(i->first, key_backends);
      std::sort(key_backends.begin(), key_backends.end());

      auto a = key_backends.begin();
      auto b = i;

      while (a != key_backends.end()) {
        if (*a < b->second || b == j) {
          std::uniform_int_distribution<size_t> dist(0, j - i - 1);
          auto source = i + dist(rng);
          moves.Add(source->first, source->second, *a);
          ++a;
        } else if (b->second < *a) {
          removals.Add(b->first, b->second);
          ++b;
        } else {
          ++a;
          ++b;
        }
      }

      while (b != j) {
        removals.Add(b->first, b->second);
        ++b;
      }

      progress.Put(j - i);
      i = j;
    }
  }

  fprintf(stderr,
          "%zu objects (%zu unique).  %zu moves and %zu removals required\n",
          object_presence.size(), unique_objects, moves.size(),
          removals.size());

  object_presence.clear();
  object_presence.shrink_to_fit();

  moves.RunQueue(backends.size() * 2);
  removals.RunQueue(backends.size() * 10);
}

bool Export(CASClient* client, char** argv, int argc) {
  std::unordered_set<CASKey> objects;

  if (argc == 1) {
    kj::AutoCloseFd input(nullptr);
    if (!strcmp(argv[0], "-")) {
      input = kj::AutoCloseFd(STDIN_FILENO);
    } else {
      input = cas_internal::OpenFile(argv[0], O_RDONLY);
    }

    cas_internal::ReadLines<string_view>(input, [&objects](auto&& key) {
      objects.emplace(CASKey::FromString(key));
    });
  } else {
    if (argc != 0) {
      err(EX_USAGE, "The 'export' command takes 1 or 0 arguments, %d given",
          argc);
    }

    client
        ->ListAsync([&objects](const CASKey& key) { objects.emplace(key); },
                    list_mode, min_size, max_size)
        .wait(aio_context->waitScope);
  }

  for (const auto& exclude_path : exclude_paths) {
    cantera::ColumnFileReader reader(
        cas_internal::OpenFile(exclude_path.c_str(), O_RDONLY));
    reader.SetColumnFilter({0});

    while (!reader.End()) {
      const auto row = reader.GetRow();

      KJ_REQUIRE(row.size() == 1, row.size());
      KJ_REQUIRE(row[0].first == 0, row[0].first);
      KJ_REQUIRE(static_cast<bool>(row[0].second));

      const auto& key = row[0].second.value();
      KJ_REQUIRE(key.size() == 20, key.size());

      objects.erase(CASKey(reinterpret_cast<const uint8_t*>(key.data())));
    }
  }

  std::vector<CASKey> queue(objects.begin(), objects.end());

  // Free memory used by `objects`.
  objects = std::unordered_set<CASKey>();

  ExportQueue exports(client, std::move(queue));
  exports.RunQueue(100);

  return true;
}

}  // namespace

int main(int argc, char** argv) try {
  aio_context = std::make_unique<kj::AsyncIoContext>(kj::setupAsyncIo());
  KJ_DEFER(aio_context.reset());

  const char* server_addr = getenv("CA_CAS_SERVER");

  int i;
  while ((i = getopt_long(argc, argv, "", kLongOptions, 0)) != -1) {
    if (i == 0) continue;
    if (i == '?')
      errx(EX_USAGE, "Try '%s --help' for more information.", argv[0]);
    switch (static_cast<Option>(i)) {
      case kOptionCompression:
        compression =
            cantera::ColumnFileWriter::StringToCompressingAlgorithm(optarg);
        break;

      case kOptionExclude: {
        glob_t globbuf;
        memset(&globbuf, 0, sizeof(globbuf));
        KJ_REQUIRE(0 <= glob(optarg, GLOB_ERR, nullptr, &globbuf));
        for (size_t i = 0; i < globbuf.gl_pathc; ++i)
          exclude_paths.emplace_back(globbuf.gl_pathv[i]);
        globfree(&globbuf);
      } break;

      case kOptionListMode:
        if (!strcmp(optarg, "default"))
          list_mode = CAS::ListMode::DEFAULT;
        else if (!strcmp(optarg, "garbage"))
          list_mode = CAS::ListMode::GARBAGE;
        else
          errx(EX_USAGE, "Unknown list mode '%s'", optarg);
        break;

      case kOptionMaxSize:
        max_size = cas_internal::StringToUInt64(optarg);
        break;

      case kOptionMinSize:
        min_size = cas_internal::StringToUInt64(optarg);
        break;

      case kOptionServerAddress:
        server_addr = optarg;
        break;
    }
  }

  if (print_help) {
    printf(
        "Usage: %s [OPTION]... COMMAND [ARGUMENT]...\n"
        "\n"
        "      --server=SERVER:PORT   connect to SERVER:PORT\n"
        "      --help     display this help and exit\n"
        "      --version  display version information and exit\n"
        "\n"
        "Filter options:\n"
        "      --exclude=GLOB         skip objects listed in files matching "
        "GLOB\n"
        "      --list-mode=MODE       select list mode:\n"
        "                               default: only non-garbage objects\n"
        "                               garbage: only garbage objects\n"
        "      --min-size=SIZE        skip objects smaller than SIZE\n"
        "      --max-size=SIZE        skip objects not smaller than SIZE\n"
        "\n"
        "Garbage collection commands:\n"
        "  begin-gc                   starts a garbage colleciton cycle\n"
        "                             and prints the ID required to end it\n"
        "  mark-gc KEY...             marks objects as NOT garbage\n"
        "  end-gc ID                  removes all non-marked objects from the "
        "given\n"
        "                             cycle.  Reports a failure if another "
        "cycle has\n"
        "                             started after it\n"
        "\n"
        "Other commands:\n"
        "  balance CONFIG             ensures proper object placement after "
        "outage\n"
        "  capacity                   prints capacity figures\n"
        "  compact                    free disk space used by deleted objects\n"
        "  export [PATH]...           export objects listed on standard input, "
        "or in\n"
        "                                the given files (subject to filters)\n"
        "  get KEY...                 retrieves the given objects\n"
        "  list                       lists all objects (subject to filters)\n"
        "  ping                       connect, then disconnect\n"
        "  put [PATH]...              inserts object from standard input, or "
        "in the\n"
        "                             given files\n"
        "  rm KEY...                  permanently removes the given objects\n"
        "\n"
        "Exports and object lists passed to `--exclude' are column files where "
        "the\n"
        "first column is the binary representation of the object keys.\n"
        "\n"
        "Report bugs to <morten.hustveit@gmail.com>\n",
        argv[0]);

    return EXIT_SUCCESS;
  }

  if (print_version) {
    puts(PACKAGE_STRING);
    return EXIT_SUCCESS;
  }

  if (!server_addr) server_addr = "localhost:6001";

  if (optind == argc)
    errx(EX_USAGE, "Usage: %s [OPTION]... COMMAND [ARGUMENTS...]", argv[0]);

  KJ_REQUIRE(min_size < max_size, min_size, max_size);

  std::string command_name = argv[optind++];
  std::function<bool(CASClient * client, char** argv, int argc)> command;

  if (command_name == "balance") {
    Balance(argv + optind, argc - optind);
    return EXIT_SUCCESS;
  } else if (command_name == "capacity") {
    command = Capacity;
  } else if (command_name == "compact") {
    command = Compact;
  } else if (command_name == "export") {
    command = Export;
  } else if (command_name == "get") {
    command = Get;
  } else if (command_name == "begin-gc") {
    command = BeginGC;
  } else if (command_name == "mark-gc") {
    command = MarkGC;
  } else if (command_name == "end-gc") {
    command = EndGC;
  } else if (command_name == "list") {
    command = List;
  } else if (command_name == "ping") {
    command = Ping;
  } else if (command_name == "put") {
    command = Put;
  } else if (command_name == "rm") {
    KJ_REQUIRE(!no_remove);
    command = Remove;
  } else {
    errx(EX_USAGE, "Unknown command: %s", command_name.c_str());
  }

  auto client = std::make_unique<CASClient>(server_addr, *aio_context);

  const auto status = command(client.get(), argv + optind, argc - optind);

  return status ? EXIT_SUCCESS : EXIT_FAILURE;
} catch (kj::Exception e) {
  KJ_LOG(FATAL, e);
  return EXIT_FAILURE;
}
