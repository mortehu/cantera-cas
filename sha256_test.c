#include "sha256.h"

#include <assert.h>
#include <string.h>

static const struct
{
  const unsigned char digest[32];
  const char *key;
  const char *message;
} test_vectors[] =
{
  /* Test vectors from RFC 4231.  */
    {
        { 0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf,
          0xce, 0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83,
          0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7 },
        "\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v",
        "Hi There"
    },
    {
        { 0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24,
          0x26, 0x08, 0x95, 0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27,
          0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43 },
        "Jefe",
        "what do ya want for nothing?"
    },
    {
        { 0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 0x85, 0x4d, 0xb8,
          0xeb, 0xd0, 0x91, 0x81, 0xa7, 0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8,
          0xc1, 0x22, 0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe },
        "\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252",
        "\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335\335"
    },
    {
        { 0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26,
          0xaa, 0xcb, 0xf5, 0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28,
          0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54 },
        "\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252",
        "Test Using Larger Than Block-Size Key - Hash Key First"
    },
};

static void
check_sha256_hmac (void)
{
  size_t i;

  for (i = 0; i < sizeof(test_vectors) / sizeof (test_vectors[0]); ++i)
    {
      unsigned char result[32];

      sha256_hmac (result,
                   test_vectors[i].key, strlen (test_vectors[i].key),
                   test_vectors[i].message, strlen (test_vectors[i].message));

      assert (!memcmp (result, test_vectors[i].digest, 32));
    }
}

int
main (int argc, char **argv)
{
  check_sha256_hmac ();

  return EXIT_SUCCESS;
}
