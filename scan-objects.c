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
#include <sys/mman.h>
#include <unistd.h>

#if HAVE_LINUX_FIEMAP_H
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#endif

#include "ca-cas.h"
#include "ca-cas-internal.h"

struct object_array
{
  struct ca_cas_object *objects;
  size_t object_count, object_alloc;
};

static int
collect_object (struct ca_cas_object *object, void *arg)
{
  struct object_array *objects = arg;

  if (objects->object_count == objects->object_alloc)
    {
      struct ca_cas_object *new_objects;
      size_t new_alloc;

      if (objects->object_alloc)
        new_alloc = objects->object_alloc * 3 / 2;
      else
        new_alloc = 4096;

      if (!(new_objects = realloc (objects->objects,
                                   sizeof (*objects->objects) * new_alloc)))
        {
          ca_cas_set_error ("realloc failed: %s", strerror (errno));

          return -1;
        }

      objects->objects = new_objects;
      objects->object_alloc = new_alloc;
    }

  objects->objects[objects->object_count++] = *object;

  return 0;
}

int
get_objects (struct ca_cas_object **ret_objects, size_t *ret_object_count,
             unsigned int flags)
{
  struct object_array objects;

  memset (&objects, 0, sizeof (objects));

  int result = -1;

  if (0 == scan_objects (collect_object, flags, &objects))
    {
      *ret_objects = objects.objects;
      *ret_object_count = objects.object_count;

      result = 0;
    }
  else
    {
      *ret_objects = NULL;
      *ret_object_count = 0;

      free (objects.objects);
    }

  return result;
}

static int
scan_file_objects (int (*callback)(struct ca_cas_object *object, void *arg),
                   unsigned int flags, void *arg)
{
  static const unsigned char hex_helper[26] =
    {
      0, 10, 11, 12, 13, 14, 15,  0,
      0,  0,  0,  0,  0,  0,  0,  0,
      0,  1,  2,  3,  4,  5,  6,  7,
      8,  9
    };
  static const char valid_chars[] = "0123456789abcdef";

  struct ca_cas_object object;
  char path[43];

  DIR *root = NULL, *subdir = NULL, *subsubdir = NULL;
  struct dirent *root_ent;
  int fd = -1;
  int result = -1;

  int block_size = 0;

  if (!(root = opendir (".")))
    {
      ca_cas_set_error ("Failed to open . for reading: %s\n", strerror (errno));

      goto done;
    }

  memset (&object, 0, sizeof (object));
  path[2] = '/';
  path[5] = '/';
  path[42] = 0;

  errno = 0;

  while (NULL != (root_ent = readdir (root)))
    {
      struct dirent *subdir_ent;
      int subdirfd;

      if (2 != strspn (root_ent->d_name, valid_chars)
          || root_ent->d_name[2])
        continue;

      path[0] = root_ent->d_name[0];
      path[1] = root_ent->d_name[1];
      object.sha1[0] = ((hex_helper[path[0] & 0x1f] << 4)
                        | (hex_helper[path[1] & 0x1f]));

      if (-1 == (subdirfd = open (root_ent->d_name, O_DIRECTORY | O_RDONLY)))
        {
          ca_cas_set_error ("Failed to open %s for reading: %s\n",
                            root_ent->d_name, strerror (errno));

          goto done;
        }

      if (!(subdir = fdopendir (subdirfd)))
        {
          ca_cas_set_error ("fdopendir failed: %s\n", strerror (errno));

          close (subdirfd);

          goto done;
        }

      while (NULL != (subdir_ent = readdir (subdir)))
        {
          struct dirent *subsubdir_ent;
          int subsubdirfd;

          if (2 != strspn (subdir_ent->d_name, valid_chars)
              || subdir_ent->d_name[2])
            continue;

          path[3] = subdir_ent->d_name[0];
          path[4] = subdir_ent->d_name[1];
          object.sha1[1] = ((hex_helper[path[3] & 0x1f] << 4)
                            | (hex_helper[path[4] & 0x1f]));

          if (-1 == (subsubdirfd = openat (subdirfd, subdir_ent->d_name,
                                           O_DIRECTORY | O_RDONLY)))
            {
              ca_cas_set_error ("Failed to open %s/%s for reading: %s\n",
                                root_ent->d_name, subdir_ent->d_name,
                                strerror (errno));

              goto done;
            }

          if (!(subsubdir = fdopendir (subsubdirfd)))
            {
              ca_cas_set_error ("fdopendir failed: %s\n", strerror (errno));

              close (subsubdirfd);

              goto done;
            }

          while (NULL != (subsubdir_ent = readdir (subsubdir)))
            {
              int i;

              if (36 != strspn (subsubdir_ent->d_name, valid_chars)
                  || subsubdir_ent->d_name[36])
                continue;

              memcpy (path + 6, subsubdir_ent->d_name, 36);

              for (i = 0; i < 36; i += 2)
                {
                  object.sha1[2 + i / 2] = ((hex_helper[path[i + 6] & 0x1f] << 4)
                                            | (hex_helper[path[i + 7] & 0x1f]));
                }

              if (0 != (flags & CA_CAS_INCLUDE_OFFSETS))
                {
                  struct
                    {
                      struct fiemap fiemap;
                      struct fiemap_extent extent;
                    } fm;

                  if (-1 == (fd = open (path, O_RDONLY)))
                    {
                      ca_cas_set_error ("failed to open '%s' for reading: %s",
                                        path, strerror (errno));

                      goto done;
                    }

                  if (!block_size
                      && -1 == ioctl (fd, FIGETBSZ, &block_size))
                    {
                      ca_cas_set_error ("failed to get block size of '%s': %s",
                                        path, strerror (errno));

                      goto done;
                    }

                  memset (&fm, 0, sizeof (fm));
                  fm.fiemap.fm_start = 0;
                  fm.fiemap.fm_length = block_size;
                  fm.fiemap.fm_flags = 0;
                  fm.fiemap.fm_extent_count = 1;

                  if (-1 == ioctl (fd, FS_IOC_FIEMAP, (unsigned long) &fm))
                    {
                      ca_cas_set_error ("FS_IOC_FIEMAP failed for '%s': %s",
                                        path, strerror (errno));

                      goto done;
                    }

                  object.phys_offset = fm.fiemap.fm_extents[0].fe_physical;

                  close (fd);
                  fd = -1;
                }

              if (-1 == callback (&object, arg))
                goto done;
            }

          closedir (subsubdir);
          subsubdir = NULL;
        }

      if (errno)
        {
          ca_cas_set_error ("readdir failed: %s", strerror (errno));

          goto done;
        }

      closedir (subdir);
      subdir = NULL;
    }

  if (errno)
    {
      ca_cas_set_error ("readdir failed: %s", strerror (errno));

      goto done;
    }


  result = 0;

done:

  if (fd != -1)
    close (fd);

  if (subsubdir)
    closedir (subsubdir);

  if (subdir)
    closedir (subdir);

  if (root)
    closedir (root);

  return result;
}

static int
scan_pack_objects (int (*callback)(struct ca_cas_object *object, void *arg),
                   unsigned int flags, void *arg)
{
  struct ca_cas_object object;

  const struct ca_cas_pack_handle *packs;
  ssize_t i, pack_count;

  memset (&object, 0, sizeof (object));

  if (-1 == (pack_count = CA_cas_pack_get_handles (&packs)))
    return -1;

  for (i = 0; i < pack_count; ++i)
    {
      const struct ca_cas_pack_handle *pack = &packs[i];
      size_t j;

      for (j = 0; j < pack->header->entry_count; ++j)
        {
          if (!pack->entries[j].offset)
            continue;

          memcpy (object.sha1, pack->entries[j].sha1, sizeof (object.sha1));

          object.pack = pack;
          object.phys_offset = j;

          if (-1 == callback (&object, arg))
            return -1;
        }
    }

  return 0;
}

int
scan_objects (int (*callback)(struct ca_cas_object *object, void *arg),
              unsigned int flags, void *arg)
{
  if (0 != (flags & CA_CAS_SCAN_FILES))
    {
      if (-1 == scan_file_objects (callback, flags, arg))
        return -1;
    }

  if (0 != (flags & CA_CAS_SCAN_PACKS))
    {
      if (-1 == scan_pack_objects (callback, flags, arg))
        return -1;
    }

  return 0;
}
