/*
    Content addressable storage repacking tool
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dirent.h>
#include <err.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sysexits.h>
#include <unistd.h>

#include "ca-cas.h"

static int print_version;
static int print_help;

static struct option long_options[] =
{
    { "version",        no_argument,  &print_version, 1 },
    { "help",           no_argument,  &print_help,    1 },
    { 0, 0, 0, 0 }
};

static int
dir_filter (const struct dirent *ent)
{
  return isxdigit (ent->d_name[0]) && isxdigit (ent->d_name[1]) && !ent->d_name[2];
}

static void
write_pack (const unsigned char *hashes, size_t hash_count)
{
  char tmp_path[16];

  struct pack_header *header;
  struct pack_entry *entries;
  off_t size;
  int pack_fd;

  size_t i;

  if (-1 == mkdir ("packs", 0777) && errno != EEXIST)
    err (EXIT_FAILURE, "mkdir failed");

  sprintf (tmp_path, "pack.tmp.XXXXXX");

  /* XXX: unlink temporary file on failure */

  if (-1 == (pack_fd = mkstemp (tmp_path)))
    err (EXIT_FAILURE, "%s: mkstemp failed", tmp_path);

  size = sizeof (*header) + hash_count * 2 * sizeof (*entries);

  if (-1 == ftruncate (pack_fd, size))
    err (EXIT_FAILURE, "%s: ftruncate failed", tmp_path);

  if (-1 == lseek (pack_fd, size, SEEK_SET))
    err (EXIT_FAILURE, "%s: seek failed", tmp_path);

  if (MAP_FAILED == (header = mmap (NULL, (size_t) size, PROT_WRITE, MAP_SHARED, pack_fd, 0)))
    err (EXIT_FAILURE, "mmap failed");

  header->magic = PACK_MAGIC;
  header->entry_count = hash_count * 2;

  entries = (struct pack_entry *) (header + 1);

  for (i = 0; i < hash_count; ++i)
    {
      uint64_t j;
      const unsigned char *sha1;

      char entity_path[43];
      int ret = 0, entity_fd;
      off_t offset = 0, entity_size;

      sha1 = hashes + i * 20;

      j = (uint64_t) sha1[0] << 56
        | (uint64_t) sha1[1] << 48
        | (uint64_t) sha1[2] << 40
        | (uint64_t) sha1[3] << 32
        | (uint64_t) sha1[4] << 24
        | (uint64_t) sha1[5] << 16
        | (uint64_t) sha1[6] << 8
        | (uint64_t) sha1[7];
      j %= header->entry_count;

      while (entries[j].offset)
        {
          if (++j == header->entry_count)
            j = 0;
        }

      entries[j].offset = size;

      sha1_to_path (entity_path, sha1);

      if (-1 == (entity_fd = open (entity_path, O_RDONLY)))
        err (EXIT_FAILURE, "%s: open failed", entity_path);

      if (-1 == (entity_size = lseek (entity_fd, 0, SEEK_END)))
        err (EXIT_FAILURE, "%s: failed to seek to end of file", entity_path);

      if (-1 == lseek (entity_fd, 0, SEEK_SET))
        err (EXIT_FAILURE, "%s: failed to seek to beginning of file", entity_path);

      while (offset < entity_size
             && -1 != (ret = sendfile (pack_fd, entity_fd, NULL, entity_size - offset)))
        offset += ret;

      if (ret == -1)
        err (EXIT_FAILURE, "%s: sendfile failed", entity_path);

      entries[j].size = entity_size;
      memcpy (entries[j].sha1, sha1, 20);

      close (entity_fd);

      size += entity_size;
    }

  if (-1 == fsync (pack_fd))
    err (EXIT_FAILURE, "%s: sync failed", tmp_path);

  close (pack_fd);

  for (i = 0; ; ++i)
    {
      char path[64];

      sprintf (path, "packs/%08zx.pack", i);

      if (0 == access (path, F_OK))
        continue;

      if (errno != ENOENT)
        err (EXIT_FAILURE, "%s: acces failed", path);

      if (-1 == rename (tmp_path, path))
        err (EXIT_FAILURE, "%s: failed to rename to %s", tmp_path, path);

      break;
    }

  /* Now that the entities are in a synced .pack file, they can be removed */

  for (i = 0; i < hash_count; ++i)
    {
      const unsigned char *sha1;

      char entity_path[43];

      sha1 = hashes + i * 20;

      sha1_to_path (entity_path, sha1);

      unlink (entity_path);
    }
}

int
main (int argc, char **argv)
{
  static const unsigned char hex_helper[26] =
    {
      0, 10, 11, 12, 13, 14, 15,  0,
      0,  0,  0,  0,  0,  0,  0,  0,
      0,  1,  2,  3,  4,  5,  6,  7,
      8,  9
    };

  unsigned char *hashes = NULL;
  size_t hash_count = 0, hash_alloc = 0;

  struct dirent **dir_ents;
  int i, dir_count;

  while ((i = getopt_long (argc, argv, "c:", long_options, 0)) != -1)
    {
      switch (i)
        {
        case 0:

          break;

        case '?':

          errx (EX_USAGE, "Try '%s --help' for more information.", argv[0]);
        }
    }

  if (print_help)
    {
      printf ("Usage: %s [OPTION]...\n"
             "\n"
             "      --help     display this help and exit\n"
             "      --version  display version information and exit\n"
             "\n"
             "Report bugs to <morten.hustveit@gmail.com>\n",
             argv[0]);

      return EXIT_SUCCESS;
    }

  if (print_version)
    {
      fprintf (stdout, "%s\n", PACKAGE_STRING);

      return EXIT_SUCCESS;
    }

  if (optind + 1 == argc)
    {
      if (-1 == chdir (argv[optind]))
        err (EXIT_FAILURE, "Unable to chdir to '%s'", argv[optind]);
    }
  else if (optind + 1 < argc)
    errx (EX_USAGE, "Usage: %s [OPTION]... [PATH]", argv[0]);

  if (-1 == (dir_count = scandir(".", &dir_ents, dir_filter, alphasort)))
    err (EXIT_FAILURE, "scandir failed");

  for (i = 0; i < dir_count; ++i)
    {
      struct dirent **subdir_ents;
      int j, subdir_count;
      char path[6];

      path[0] = dir_ents[i]->d_name[0];
      path[1] = dir_ents[i]->d_name[1];
      path[2] = '/';
      path[5] = 0;

      if (-1 == (subdir_count = scandir(dir_ents[i]->d_name, &subdir_ents, dir_filter, alphasort)))
        err (EXIT_FAILURE, "%s: scandir failed", dir_ents[i]->d_name);

      for (j = 0; j < subdir_count; ++j)
        {
          DIR *dir;
          struct dirent *ent;

          path[3] = subdir_ents[j]->d_name[0];
          path[4] = subdir_ents[j]->d_name[1];

          if (!(dir = opendir (path)))
            err (EXIT_FAILURE, "%s: opendir failed", path);

          errno = 0;

          while (NULL != (ent = readdir (dir)))
            {
              unsigned int k;
              unsigned char *sha1;

              if (hash_count == hash_alloc)
                {
                  void *new_hashes;
                  size_t new_alloc;

                  if (hash_alloc)
                    new_alloc = hash_alloc * 3 / 2;
                  else
                    new_alloc = 4096;

                  if (!(new_hashes = realloc (hashes, 20 * new_alloc)))
                    err (EXIT_FAILURE, "realloc failed");

                  hashes = new_hashes;
                  hash_alloc = new_alloc;
                }

              sha1 = hashes + 20 * hash_count;

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

              ++hash_count;
            }

          if (errno)
            err (EXIT_FAILURE, "%s: readdir failed", path);

          closedir (dir);
        }
    }

  write_pack (hashes, hash_count);

  return EXIT_SUCCESS;
}
