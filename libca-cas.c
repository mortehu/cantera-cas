#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "ca-cas.h"

struct ca_cas_context
{
  FILE *stream;
};

static int
write_all (FILE *stream, const void *data, size_t size);

static int
read_all (FILE *stream, void *data, size_t size);

struct ca_cas_context *
ca_cas_connect (const char *hostname)
{
  char *hostname_buffer, *port;

  struct addrinfo *addrs = NULL;
  struct addrinfo *addr;
  struct addrinfo hints;

  struct ca_cas_context *result = NULL;
  FILE *stream = NULL;
  int fd = -1;

  if (!(hostname_buffer = strdup (hostname)))
    return NULL;

  if (NULL != (port = strchr (hostname, ':')))
    *port++ = 0;

  memset(&hints, 0, sizeof(hints));
  hints.ai_protocol = getprotobyname("tcp")->p_proto;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_CANONNAME;
  hints.ai_family = PF_UNSPEC;

  getaddrinfo (hostname_buffer, port ? port : "5993", &hints, &addrs);

  if (!addrs)
    goto done;

  for (addr = addrs; addr; addr = addr->ai_next)
    {
      fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);

      if (fd == -1)
        continue;

      if (-1 != connect (fd, addr->ai_addr, addr->ai_addrlen))
        break;

      close(fd);
      fd = -1;
    }

  if (fd == -1)
    goto done;

  if (!(stream = fdopen (fd, "r+")))
    goto done;

  fd = -1;

  if (!(result = calloc (1, sizeof (*result))))
    goto done;

  result->stream = stream;
  stream = NULL;

done:

  if (stream)
    fclose (stream);
  else if (fd != -1)
    close (fd);

  free (hostname_buffer);

  return result;
}

void
ca_cas_free (struct ca_cas_context *ctx)
{
  if (ctx->stream)
    fclose (ctx->stream);

  free (ctx);
}

ssize_t
ca_cas_get (struct ca_cas_context *ctx,
            const unsigned char sha1[static 20], void **data)
{
  char buffer[47];
  size_t buffer_length = 0;
  ssize_t result;

  strcpy (buffer, "GET ");
  ca_cas_sha1_to_hex (sha1, buffer + 4);
  buffer[44] = '\n';
  buffer[45] = 0;

  if (-1 == write_all (ctx->stream, buffer, 46))
    goto fail;

  if (!(fgets (buffer, sizeof (buffer), ctx->stream)))
    goto fail;

  buffer_length = strlen (buffer);

  if (!buffer_length || buffer[buffer_length - 1] != '\n')
    goto fail;

  buffer[--buffer_length] = 0;

  if (strncmp (buffer, "200 ", 4))
    goto fail;

  if (0 > (result = (ssize_t) strtoll (buffer + 4, NULL, 10)))
    goto fail;

  if (!(*data = malloc (result)))
    goto fail;

  if (-1 == read_all (ctx->stream, *data, result))
    goto fail;

  return result;

fail:

  fclose (ctx->stream);
  ctx->stream = NULL;

  return -1;
}

int
ca_cas_put (struct ca_cas_context *ctx,
            unsigned char sha1[static 20], const void *data, size_t size)
{
  char buffer[47];
  size_t buffer_length = 0;

  if (0 > fprintf (ctx->stream, "PUT %llu\n", (unsigned long long) size)
      || -1 == write_all (ctx->stream, data, size))
    goto fail;

  if (!(fgets (buffer, sizeof (buffer), ctx->stream)))
    goto fail;

  buffer_length = strlen (buffer);

  if (!buffer_length || buffer[buffer_length - 1] != '\n')
    goto fail;

  buffer[--buffer_length] = 0;

  if (strncmp (buffer, "201 ", 4))
    goto fail;

  ca_cas_hex_to_sha1 (sha1, buffer + 4);

  return 0;

fail:

  fclose (ctx->stream);
  ctx->stream = NULL;

  return -1;
}

void
ca_cas_sha1_to_hex (const unsigned char sha1[static 20], char hex[static 41])
{
  static const char hex_digits[] = "0123456789abcdef";
  unsigned int i;

  for (i = 0; i < 20; ++i)
    {
      hex[i * 2 + 0] = hex_digits[sha1[i] >> 4];
      hex[i * 2 + 1] = hex_digits[sha1[i] & 15];
    }

  hex[40] = 0;
}

int
ca_cas_hex_to_sha1 (unsigned char sha1[static 20], const char *hex)
{
  static const unsigned char helper[26] =
    {
      0, 10, 11, 12, 13, 14, 15,  0,
      0,  0,  0,  0,  0,  0,  0,  0,
      0,  1,  2,  3,  4,  5,  6,  7,
      8,  9
    };

  unsigned int i;
  unsigned char *out;

  out = sha1;

  for (i = 0; i < 20; ++i, hex += 2)
    {
      if (!isxdigit (hex[0]) || !isxdigit (hex[1]))
        {
          errno = EINVAL;

          return -1;
        }

      /* Works with both upper- and lower-case */
      *out++ = (helper[hex[0] & 0x1f] << 4)
             | (helper[hex[1] & 0x1f]);
    }

  /* Verify no garbage after end of SHA-1 */
  if (*hex)
    {
      errno = EINVAL;

      return -1;
    }

  return 0;
}

static int
write_all (FILE *stream, const void *data, size_t size)
{
  const char *cdata = data;
  size_t ret;

  while (size)
    {
      if (0 > (ret = fwrite (cdata, 1, size, stream)))
        return -1;

      size -= ret;
      cdata += ret;
    }

  return 0;
}

static int
read_all (FILE *stream, void *data, size_t size)
{
  char *cdata = data;
  size_t ret;

  while (size)
    {
      if (0 > (ret = fread (cdata, 1, size, stream)))
        return -1;

      size -= ret;
      cdata += ret;
    }

  return 0;
}
