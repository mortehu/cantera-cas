/* Computes the 256 bit SHA-256 hash of a byte oriented message.  */

#include "sha256.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

void sha256_init(struct sha256_context *state) {
  state->size = 0;
  state->h[0] = 0x6a09e667;
  state->h[1] = 0xbb67ae85;
  state->h[2] = 0x3c6ef372;
  state->h[3] = 0xa54ff53a;
  state->h[4] = 0x510e527f;
  state->h[5] = 0x9b05688c;
  state->h[6] = 0x1f83d9ab;
  state->h[7] = 0x5be0cd19;
  state->buffer_fill = 0;
}

static void sha256_consume(struct sha256_context *state) {
  static const uint32_t k[64] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

  uint32_t w[64];
  uint32_t s0, s1, maj, ch, t1, t2;
  uint32_t a, b, c, d, e, f, g, h;
  unsigned int i;

  for (i = 0; i < 16; ++i) {
    w[i] = (state->buffer[i * 4 + 0] << 24) | (state->buffer[i * 4 + 1] << 16) |
           (state->buffer[i * 4 + 2] << 8) | state->buffer[i * 4 + 3];
  }

  for (i = 16; i < 64; ++i) {
    s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
    s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  a = state->h[0];
  b = state->h[1];
  c = state->h[2];
  d = state->h[3];
  e = state->h[4];
  f = state->h[5];
  g = state->h[6];
  h = state->h[7];

  for (i = 0; i < 64; ++i) {
    s0 = ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22);
    maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = s0 + maj;
    s1 = ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25);
    ch = (e & f) ^ (~e & g);
    t1 = h + s1 + ch + k[i] + w[i];

    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  state->h[0] += a;
  state->h[1] += b;
  state->h[2] += c;
  state->h[3] += d;
  state->h[4] += e;
  state->h[5] += f;
  state->h[6] += g;
  state->h[7] += h;

  state->buffer_fill = 0;
}

void sha256_add(struct sha256_context *state, const void *data, size_t size) {
  size_t amount;

  state->size += size * 8;

  while (state->buffer_fill + size >= sizeof(state->buffer)) {
    amount = sizeof(state->buffer) - state->buffer_fill;

    memcpy(state->buffer + state->buffer_fill, data, amount);

    state->buffer_fill += amount;

    sha256_consume(state);

    data = (char *)data + amount;
    size -= amount;
  }

  memcpy(state->buffer + state->buffer_fill, data, size);

  state->buffer_fill += size;
}

void sha256_finish(struct sha256_context *state,
                   unsigned char hash[static 32]) {
  unsigned int i;

  state->buffer[state->buffer_fill++] = 0x80;

  while (state->buffer_fill != 56) {
    if (state->buffer_fill == sizeof(state->buffer)) sha256_consume(state);

    state->buffer[state->buffer_fill++] = 0;
  }

  state->buffer[state->buffer_fill++] = state->size >> 56;
  state->buffer[state->buffer_fill++] = state->size >> 48;
  state->buffer[state->buffer_fill++] = state->size >> 40;
  state->buffer[state->buffer_fill++] = state->size >> 32;
  state->buffer[state->buffer_fill++] = state->size >> 24;
  state->buffer[state->buffer_fill++] = state->size >> 16;
  state->buffer[state->buffer_fill++] = state->size >> 8;
  state->buffer[state->buffer_fill++] = state->size;

  sha256_consume(state);

  for (i = 0; i < 32; i += 4) {
    hash[i] = state->h[i / 4] >> 24;
    hash[i + 1] = state->h[i / 4] >> 16;
    hash[i + 2] = state->h[i / 4] >> 8;
    hash[i + 3] = state->h[i / 4];
  }
}

void sha256_hmac_init(struct sha256_context *state, const void *key,
                      size_t key_size) {
  unsigned char buffer[64];
  size_t i;

  if (key_size > sizeof(buffer)) {
    sha256_init(state);
    sha256_add(state, key, key_size);
    sha256_finish(state, buffer);

    for (i = 0; i < 32; ++i) buffer[i] ^= 0x36;
  } else {
    for (i = 0; i < key_size; ++i) buffer[i] = ((unsigned char *)key)[i] ^ 0x36;
  }

  for (; i < sizeof(buffer); ++i) buffer[i] = 0x36;

  sha256_init(state);
  sha256_add(state, buffer, sizeof(buffer));
}

void sha256_hmac_finish(struct sha256_context *state, const void *key,
                        size_t key_size, unsigned char hash[static 32]) {
  unsigned char buffer[64], intermediate[32];
  size_t i;

  sha256_finish(state, intermediate);

  if (key_size > sizeof(buffer)) {
    sha256_init(state);
    sha256_add(state, key, key_size);
    sha256_finish(state, buffer);

    for (i = 0; i < 32; ++i) buffer[i] ^= 0x5c;
  } else {
    for (i = 0; i < key_size; ++i) buffer[i] = ((unsigned char *)key)[i] ^ 0x5c;
  }

  for (; i < sizeof(buffer); ++i) buffer[i] = 0x5c;

  sha256_init(state);
  sha256_add(state, buffer, sizeof(buffer));
  sha256_add(state, intermediate, sizeof(intermediate));
  sha256_finish(state, hash);
}

void sha256_hmac(unsigned char result[static 32], const void *key,
                 size_t key_size, const void *message, size_t message_size) {
  struct sha256_context sha256;

  sha256_hmac_init(&sha256, key, key_size);
  sha256_add(&sha256, message, message_size);
  sha256_hmac_finish(&sha256, key, key_size, result);
}
