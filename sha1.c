/*
    Computes the 160 bit SHA-1 hash of a byte oriented message
    Copyright (C) 2011    Morten Hustveit

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "sha1.h"

void
sha1_init (struct sha1_context *state)
{
  state->size = 0;
  state->h[0] = 0x67452301;
  state->h[1] = 0xefcdab89;
  state->h[2] = 0x98badcfe;
  state->h[3] = 0x10325476;
  state->h[4] = 0xc3d2e1f0;
  state->buffer_fill = 0;
}

static void
sha1_consume (struct sha1_context *state)
{
  uint32_t w[80];
  uint32_t a, b, c, d, e, f, k, temp;
  unsigned int i;

  for (i = 0; i < 16; ++i)
    {
      w[i] = (state->buffer[i * 4 + 0] << 24) | (state->buffer[i * 4 + 1] << 16)
           | (state->buffer[i * 4 + 2] << 8) | state->buffer[i * 4 + 3];
    }

  for (i = 16; i < 80; ++i)
    {
      w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]);
      w[i] = (w[i] << 1) | (w[i] >> 31);
    }

  a = state->h[0];
  b = state->h[1];
  c = state->h[2];
  d = state->h[3];
  e = state->h[4];

  for (i = 0; i < 80; ++i)
    {
      if (i < 20)
        {
          f = (b & c) | (~b & d);
          k = 0x5a827999;
        }
      else if (i < 40)
        {
          f = b ^ c ^ d;
          k = 0x6ed9eba1;
        }
      else if (i < 60)
        {
          f = (b & c) | (b & d) | (c & d);
          k = 0x8f1bbcdc;
        }
      else
        {
          f = b ^ c ^ d;
          k = 0xca62c1d6;
        }

      temp = ((a << 5) | (a >> 27)) + f + e + k + w[i];
      e = d;
      d = c;
      c = (b << 30) | (b >> 2);
      b = a;
      a = temp;
    }

  state->h[0] += a;
  state->h[1] += b;
  state->h[2] += c;
  state->h[3] += d;
  state->h[4] += e;

  state->buffer_fill = 0;
}

void
sha1_add (struct sha1_context *state, const void *data, size_t size)
{
  size_t amount;

  state->size += size * 8;

  while (state->buffer_fill + size >= sizeof (state->buffer))
    {
      amount = sizeof (state->buffer) - state->buffer_fill;

      memcpy (state->buffer + state->buffer_fill, data, amount);

      state->buffer_fill += amount;

      sha1_consume (state);

      data = (char *) data + amount;
      size -= amount;
    }

  memcpy (state->buffer + state->buffer_fill, data, size);

  state->buffer_fill += size;
}

void
sha1_finish (struct sha1_context *state, unsigned char *hash)
{
  unsigned int i;

  state->buffer[state->buffer_fill++] = 0x80;

  while (state->buffer_fill != 56)
    {
      if (state->buffer_fill == sizeof (state->buffer))
        sha1_consume (state);

      state->buffer[state->buffer_fill++] = 0;
    }

  for (i = 0; i < 8; ++i)
    state->buffer[state->buffer_fill++] = state->size >> (56 - i * 8);

  sha1_consume (state);

  for (i = 0; i < 20; ++i)
    hash[i] = state->h[i / 4] >> (24 - (i & 3) * 8);
}
