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

#include <cerrno>
#include <cstdio>
#include <cstdlib>

#include <err.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>

#include <capnp/rpc-twoparty.h>
#include <kj/async-io.h>
#include <kj/debug.h>

#include "src/storage-server.h"
#include "src/util.h"

using namespace cantera;
using namespace cantera::cas_internal;

namespace {

int print_version;
int print_help;
int no_detach;
int disable_read;
const char* address = "127.0.0.1";
const char* service = "6001";

enum Option {
  kOptionAddress = 'a',
  kOptionListenFD = 'f',
  kOptionNoDetach = 'n',
  kOptionPort = 'p',
};

struct option kLongOptions[] = {
    {"version", no_argument, &print_version, 1},
    {"help", no_argument, &print_help, 1},
    {"no-detach", no_argument, &no_detach, 1},
    {"address", required_argument, nullptr, kOptionAddress},
    {"port", required_argument, nullptr, kOptionPort},
    {"disable-read", no_detach, &disable_read, 1},
    {nullptr, 0, nullptr, 0}};

}  // namespace

int main(int argc, char** argv) try {
  int i;

  while ((i = getopt_long(argc, argv, "na:p:", kLongOptions, 0)) != -1) {
    if (!i) continue;
    if (i == '?')
      errx(EX_USAGE, "Try '%s --help' for more information.", argv[0]);

    switch (static_cast<Option>(i)) {
      case kOptionAddress:
        address = optarg;
        break;

      case kOptionNoDetach:
        no_detach = 1;
        break;

      case kOptionPort:
        service = optarg;
        break;
    }
  }

  if (print_help) {
    printf(
        "Usage: %s [OPTION]... [PATH]\n"
        "\n"
        "      --disable-read         do not allow read requests\n"
        "  -n, --no-detach            don't detach from the tty\n"
        "  -a, --address=ADDRESS      IP address to bind to [%s]\n"
        "  -p, --port=PORT            select TCP port [%s]\n"
        "      --help     display this help and exit\n"
        "      --version  display version information and exit\n"
        "\n"
        "Report bugs to <morten.hustveit@gmail.com>\n",
        argv[0], address, service);

    return EXIT_SUCCESS;
  }

  if (print_version) {
    puts(PACKAGE_STRING);

    return EXIT_SUCCESS;
  }

  int syslog_option = LOG_NDELAY;
  if (isatty(STDERR_FILENO)) syslog_option |= LOG_PERROR;
  openlog("ca-casd", syslog_option, LOG_DAEMON);

  if (optind + 1 == argc) {
    if (-1 == chdir(argv[optind])) {
      syslog(LOG_ERR, "Unable to chdir to '%s': %s", argv[optind],
             strerror(errno));
      return EXIT_FAILURE;
    }
    syslog(LOG_INFO, "Starting in: %s", argv[optind]);
  } else if (optind + 1 < argc) {
    errx(EX_USAGE, "Usage: %s [OPTION]... [PATH]", argv[0]);
  }

  auto aio_context = kj::setupAsyncIo();
  auto listen_address = aio_context.provider->getNetwork()
                            .parseAddress(address, StringToUInt64(service))
                            .wait(aio_context.waitScope);

  unsigned int flags = 0;
  if (disable_read) flags |= StorageServer::kDisableRead;

  auto storage_server = kj::heap<StorageServer>(".", flags, aio_context);

  RPCListeningServer<CAS> server(aio_context, std::move(storage_server),
                                 listen_address->listen());

  if (!no_detach) {
    KJ_SYSCALL(daemon(0 /* nochdir */, 0 /* noclose */));
  }

  server.AcceptLoop().wait(aio_context.waitScope);
} catch (kj::Exception e) {
  syslog(LOG_ERR, "Error: %s:%d: %s", e.getFile(), e.getLine(),
         e.getDescription().cStr());
  return EXIT_FAILURE;
} catch (std::runtime_error e) {
  syslog(LOG_ERR, "Runtime error: %s", e.what());
  return EXIT_FAILURE;
}
