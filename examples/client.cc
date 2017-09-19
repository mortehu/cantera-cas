#include <cstdlib>

#include <kj/async-io.h>
#include <kj/debug.h>

#include "client.h"

int main(int argc, char** argv) try {
  auto aio_context = kj::setupAsyncIo();
  cantera::CASClient cas(aio_context);

  const auto data = cas.Get("da39a3ee5e6b4b0d3255bfef95601890afd80709");
} catch (kj::Exception& e) {
  KJ_LOG(FATAL, e);
  return EXIT_FAILURE;
}
