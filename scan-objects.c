/*
    Scan for objects in CAS storage
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
#include <unistd.h>

#if HAVE_LINUX_FIEMAP_H
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#endif

#include "ca-cas.h"
#include "ca-cas-internal.h"

static int
dir_filter (const struct dirent *ent)
{
  return isxdigit (ent->d_name[0]) && isxdigit (ent->d_name[1]) && !ent->d_name[2];
}

int
scan_objects (struct ca_cas_object **ret_objects, size_t *ret_object_count,
              unsigned int flags)
{
  static const unsigned char hex_helper[26] =
    {
      0, 10, 11, 12, 13, 14, 15,  0,
      0,  0,  0,  0,  0,  0,  0,  0,
      0,  1,  2,  3,  4,  5,  6,  7,
      8,  9
    };

  struct dirent **dir_ents = NULL, **subdir_ents = NULL;
  int i, j, dir_count, subdir_count;
  DIR *dir = NULL;
  int fd = -1;

  int block_size;

  int result = -1;

  struct ca_cas_object *objects = NULL;
  size_t object_count = 0, object_alloc = 0;

  *ret_objects = NULL;
  *ret_object_count = 0;

  if (-1 == (dir_count = scandir (".", &dir_ents, dir_filter, alphasort)))
    {
      ca_cas_set_error ("scandir on path '.' failed: %s", strerror (errno));

      return -1;
    }

  for (i = 0; i < dir_count; ++i)
    {
      struct dirent **subdir_ents;
      int j, subdir_count;
      char path[43];

      path[0] = dir_ents[i]->d_name[0];
      path[1] = dir_ents[i]->d_name[1];
      path[2] = '/';

      if (-1 == (subdir_count = scandir (dir_ents[i]->d_name, &subdir_ents, dir_filter, alphasort)))
        {
          ca_cas_set_error ("scandir on path '%s' failed: %s", dir_ents[i]->d_name, strerror (errno));

          goto out;
        }

      for (j = 0; j < subdir_count; ++j)
        {
          struct dirent *ent;

          path[3] = subdir_ents[j]->d_name[0];
          path[4] = subdir_ents[j]->d_name[1];
          path[5] = 0;

          if (!(dir = opendir (path)))
            {
              ca_cas_set_error ("opendir on path '%s' failed: %s", path, strerror (errno));

              goto out;
            }

          errno = 0;

          while (NULL != (ent = readdir (dir)))
            {
              unsigned int k;
              unsigned char *sha1;

              if (object_count == object_alloc)
                {
                  struct ca_cas_object *new_objects;
                  size_t new_alloc;

                  if (object_alloc)
                    new_alloc = object_alloc * 3 / 2;
                  else
                    new_alloc = 4096;

                  if (!(new_objects = realloc (objects, sizeof (*objects) * new_alloc)))
                    {
                      /* Free `objects' here to increase odds of not failing on
                       * memory allocation in ca_cas_set_error() */
                      free (objects);
                      objects = NULL;

                      ca_cas_set_error ("realloc failed: %s", strerror (errno));

                      goto out;
                    }

                  objects = new_objects;
                  object_alloc = new_alloc;
                }

            sha1 = objects[object_count].sha1;

            sha1[0] = (hex_helper[path[0] & 0x1f] << 4) | (hex_helper[path[1] & 0x1f]);
            sha1[1] = (hex_helper[path[3] & 0x1f] << 4) | (hex_helper[path[4] & 0x1f]);

            for (k = 0; k < 36; k += 2)
              {
                if (!isxdigit (ent->d_name[k]) || !isxdigit (ent->d_name[k + 1]))
                  break;

                sha1[2 + k / 2] = (hex_helper[ent->d_name[k] & 0x1f] << 4)
                                | (hex_helper[ent->d_name[k + 1] & 0x1f]);
              }

            if (k != 36 || ent->d_name[36])
              continue;

            if (0 != (flags & CA_CAS_INCLUDE_OFFSETS))
              {
                struct
                  {
                    struct fiemap fiemap;
                    struct fiemap_extent extent;
                  } fm;

                path[5] = '/';
                strcpy (&path[6], ent->d_name);

                if (-1 == (fd = open (path, O_RDONLY)))
                  {
                    ca_cas_set_error ("failed to open '%s' for reading: %s", path, strerror (errno));

                    goto out;
                  }

                if (!block_size && -1 == ioctl (fd, FIGETBSZ, &block_size))
                  {
                    ca_cas_set_error ("failed to get block size of '%s': %s", path, strerror (errno));

                    goto out;
                  }

                memset (&fm, 0, sizeof (fm));
                fm.fiemap.fm_start = 0;
                fm.fiemap.fm_length = block_size;
                fm.fiemap.fm_flags = 0;
                fm.fiemap.fm_extent_count = 1;

                if (-1 == ioctl (fd, FS_IOC_FIEMAP, (unsigned long) &fm))
                  {
                    ca_cas_set_error ("FS_IOC_FIEMAP failed for '%s': %s", path, strerror (errno));

                    goto out;
                  }

                objects[object_count].phys_offset = fm.fiemap.fm_extents[0].fe_physical;

                close (fd);
                fd = -1;
              }

              ++object_count;
            }

          if (errno)
            {
              ca_cas_set_error ("readdir on path '%s' failed: %s", path, strerror (errno));

              goto out;
            }

          closedir (dir);
          dir =  NULL;
        }

      for (j = subdir_count; j-- > 0; )
        free (subdir_ents[j]);

      free (subdir_ents);
      subdir_ents = NULL;
    }

  *ret_objects = objects;
  *ret_object_count = object_count;

  objects = NULL;

  result = 0;

out:

  free (objects);

  if (fd != -1)
    close (fd);

  if (dir)
    closedir (dir);

  if (subdir_ents)
    {
      for (j = subdir_count; j-- > 0; )
        free (subdir_ents[j]);

      free (subdir_ents);
    }

  for (i = dir_count; i-- > 0; )
    free (dir_ents[i]);

  free (dir_ents);

  return result;
}
