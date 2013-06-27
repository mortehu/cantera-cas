#ifndef SHA1_H_
#define SHA1_H_ 1

#include <stdint.h>

struct sha1_context
{
  uint64_t size;
  uint32_t h[5];
  uint32_t buffer_fill;
  uint8_t buffer[64];
};

void
sha1_init (struct sha1_context *state);

void
sha1_add (struct sha1_context *state, const void *data, size_t size);

void
sha1_finish (struct sha1_context *state, unsigned char *hash);

#endif /* !SHA1_H_ */
