#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int
path_is_rotational (const char *path)
{
  struct stat sb;
  char device_path[64]; /* Will hold any /sys/dev/block/%u:%u */
  char buf;
  int dirfd = -1, fd = -1;

  int result = -1;

  if (-1 == stat (path, &sb))
    goto out;

  if (-1 == sprintf (device_path, "/sys/dev/block/%u:%u", major (sb.st_dev), minor (sb.st_dev)))
    goto out;

  if (-1 == (dirfd = open (device_path, O_RDONLY)))
    goto out;

  for (;;)
    {
      if (-1 == (fd = openat (dirfd, "partition", O_RDONLY)))
        {
          if (errno != ENOENT)
            goto out;

          break;
        }

      close (fd);
      if (-1 == (fd = openat (dirfd, "..", O_RDONLY)))
        goto out;

      close (dirfd);
      dirfd = fd;
    }

  if (-1 == (fd = openat (dirfd, "queue/rotational", O_RDONLY)))
    goto out;

  if (1 != read (fd, &buf, 1))
    goto out;

  result = (buf == '1');

out:

  if (fd != -1)
    close (fd);

  if (dirfd != -1)
    close (dirfd);

  return result;
}
