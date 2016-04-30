#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <memory>

#include <err.h>
#include <getopt.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>

#include <kj/debug.h>
#include <yaml-cpp/yaml.h>

#include "balancer.h"
#include "rpc.h"
#include "util.h"

using namespace cantera;

namespace {

int print_version;
int print_help;
int no_detach;
const char* address = "127.0.0.1";
const char* service = "6001";

enum Option {
  kOptionAddress = 'a',
  kOptionListenFD = 'f',
  kOptionNoDetach = 'n',
  kOptionPort = 'p',
};

struct option kLongOptions[] = {
    {"address", required_argument, nullptr, kOptionAddress},
    {"no-detach", no_argument, &no_detach, 1},
    {"port", required_argument, nullptr, 'p'},
    {"version", no_argument, &print_version, 1},
    {"help", no_argument, &print_help, 1},
    {nullptr, 0, nullptr, 0}};

}  // namespace

int main(int argc, char** argv) try {
  int i;

  while ((i = getopt_long(argc, argv, "na:p:", kLongOptions, 0)) != -1) {
    switch (i) {
      case 0:
        break;

      case kOptionAddress:
        address = optarg;
        break;

      case kOptionNoDetach:
        no_detach = 1;
        break;

      case kOptionPort:
        service = optarg;
        break;

      case '?':
        errx(EX_USAGE, "Try '%s --help' for more information.", argv[0]);
    }
  }

  if (print_help) {
    printf(
        "Usage: %s [OPTION]... BACKEND...\n"
        "\n"
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

  if (optind + 1 != argc)
    errx(EX_USAGE, "Usage: %s [OPTION]... CONFIG-PATH", argv[0]);

  int syslog_option = LOG_NDELAY;
  if (isatty(STDERR_FILENO)) syslog_option |= LOG_PERROR;
  openlog("ca-cas-balancerd", syslog_option, LOG_DAEMON);

  auto aio_context = kj::setupAsyncIo();

  auto listen_address =
      aio_context.provider->getNetwork()
          .parseAddress(address, cas_internal::StringToUInt64(service))
          .wait(aio_context.waitScope);

  auto balancer_server = kj::heap<BalancerServer>(argv[optind], aio_context);

  cas_internal::RPCListeningServer<CAS> server(
      aio_context, std::move(balancer_server), listen_address->listen());

  if (!no_detach) {
    KJ_SYSCALL(daemon(0 /* nochdir */, 0 /* noclose */));
  }

  server.AcceptLoop().wait(aio_context.waitScope);
} catch (kj::Exception e) {
  KJ_LOG(ERROR, e);
  return EXIT_FAILURE;
} catch (std::runtime_error e) {
  syslog(LOG_ERR, "Runtime error: %s", e.what());
  return EXIT_FAILURE;
}
