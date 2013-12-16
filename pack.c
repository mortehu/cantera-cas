/*
    Discover and open pack files
    Copyright (C) 2013    Morten Hustveit

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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <ctype.h>
#include <errno.h>
#include <string.h>

#include <dirent.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "ca-cas.h"
#include "ca-cas-internal.h"

static struct ca_cas_pack_handle *handles;
static size_t handle_alloc, handle_count;

int CA_cas_pack_dirfd = -1;
static DIR *CA_cas_pack_dir;

ssize_t
CA_cas_pack_get_handles (const struct ca_cas_pack_handle **ret_handles)
{
  struct dirent *ent;

  const uint8_t *map = MAP_FAILED;
  off_t pack_size = 0;
  int fd = -1;

  int result = -1;

  *ret_handles = NULL;

  if (CA_cas_pack_dirfd == -1)
    {
      if (-1 == (CA_cas_pack_dirfd = open ("packs", O_DIRECTORY | O_RDONLY)))
        {
          if (errno == ENOENT)
            return 0;

          ca_cas_set_error ("Failed to open \"packs\" directory: %s", strerror (errno));

          return -1;
        }

      if (!(CA_cas_pack_dir = fdopendir (CA_cas_pack_dirfd)))
        {
          ca_cas_set_error ("fdopendir failed: %s", strerror (errno));

          close (CA_cas_pack_dirfd);
          CA_cas_pack_dirfd = -1;

          return -1;
        }
    }
  else
    {
      rewinddir (CA_cas_pack_dir);
    }

  errno = 0;

  for (;;)
    {
      const char *extension;

      struct ca_cas_pack_handle handle;
      size_t i, data_start;

      if (!(ent = readdir (CA_cas_pack_dir)))
        {
          if (!errno)
            break;

          ca_cas_set_error ("readdir failed: %s", strerror (errno));

          goto done;
        }

      if (ent->d_name[0] == '.'
          || !(extension = strrchr (ent->d_name, '.'))
          || strcmp (extension, ".pack"))
        continue;

      /* Check whether pack is already mapped.  */
      for (i = 0; i < handle_count; ++i)
        {
          if (!strcmp (handles[i].path, ent->d_name))
            break;
        }

      if (i != handle_count)
        continue;

      if (-1 == (fd = openat (CA_cas_pack_dirfd, ent->d_name, O_RDONLY)))
        {
          ca_cas_set_error ("Failed to open packs/%s for reading: %s",
                            ent->d_name, strerror (errno));

          goto done;
        }

      if (-1 == (pack_size = lseek (fd, 0, SEEK_END)))
        goto done;

      if (pack_size < sizeof (*handle.header))
        {
          ca_cas_set_error ("Short pack file header: %zu/%zu bytes",
                            pack_size, sizeof (*handle.header));

          goto done;
        }

      if (MAP_FAILED == (map = mmap (NULL, pack_size, PROT_READ, MAP_SHARED, fd, 0)))
        goto done;

      close (fd);
      fd = -1;

      handle.data = (const char *) map;
      handle.header = (const struct pack_header *) map;
      data_start = sizeof (*handle.header) + handle.header->entry_count * sizeof (*handle.entries);

      if (handle.header->magic != PACK_MAGIC)
        {
          ca_cas_set_error ("Invalid magic header in pack file.  "
                            "Expected %08x, got %08x",
                            PACK_MAGIC, handle.header->magic);

          goto done;
        }

      if (data_start > pack_size)
        {
          ca_cas_set_error ("Data pointer in pack header points beyond "
                            "end of file");

          goto done;
        }

      if (!(handle.path = strdup (ent->d_name)))
        {
          ca_cas_set_error ("strdup failed: %s", strerror (errno));

          goto done;
        }

      handle.entries = (const struct pack_entry *) (map + sizeof (*handle.header));

      if (handle_count == handle_alloc)
        {
          struct ca_cas_pack_handle *new_handles;
          size_t new_alloc;

          new_alloc = (handle_alloc + 8) * 3 / 2;

          if (!(new_handles = realloc (handles, sizeof (*handles) * new_alloc)))
            {
              ca_cas_set_error ("realloc failed: %s", strerror (errno));

              goto done;
            }

          handles = new_handles;
          handle_alloc = new_alloc;
        }

      handles[handle_count++] = handle;

      map = MAP_FAILED;
    }

  *ret_handles = handles;
  result = handle_count;

done:

  if (fd != -1)
    close (fd);

  if (map != MAP_FAILED)
    munmap ((void *) map, pack_size);

  return result;
}
