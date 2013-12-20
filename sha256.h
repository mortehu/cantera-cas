#ifndef SHA256_H_
#define SHA256_H_ 1

#include <stdint.h>
#include <stdlib.h>

struct sha256_context {
  uint64_t size;
  uint32_t h[8];
  uint32_t buffer_fill;
  uint8_t buffer[64];
};

void sha256_init(struct sha256_context *state);

void sha256_add(struct sha256_context *state, const void *data, size_t size);

void sha256_finish(struct sha256_context *state, unsigned char hash[static 32]);

void sha256_hmac_init(struct sha256_context *state, const void *key,
                      size_t key_size);

void sha256_hmac_finish(struct sha256_context *state, const void *key,
                        size_t key_size, unsigned char hash[static 32]);

/* The input message can point to the result buffer, which may be convenient if
 * you're doing multiple rounds of HMAC.  */
void sha256_hmac(unsigned char result[static 32], const void *key,
                 size_t key_size, const void *message, size_t message_size);

#endif /* !SHA256_H_ */
