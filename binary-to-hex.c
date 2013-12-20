#include "ca-cas-internal.h"

void binary_to_hex(char *output, const unsigned char *input, size_t size) {
  static const char hex[] = "0123456789abcdef";
  size_t i, o = 0;

  for (i = 0; i < size; ++i) {
    output[o++] = hex[input[i] >> 4];
    output[o++] = hex[input[i] & 15];
  }
}
