#include "ca-cas-internal.h"

void
sha1_to_path (char path[static 43], const unsigned char sha1[static 20])
{
  binary_to_hex (path,     sha1,     1);
  path[2] = '/';
  binary_to_hex (path + 3, sha1 + 1, 1);
  path[5] = '/';
  binary_to_hex (path + 6, sha1 + 2, 18);

  path[42] = 0;
}
