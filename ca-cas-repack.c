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
#include "ca-cas-internal.h"

static int print_version;
static int print_help;
static int skip_phys_sort;

static struct option long_options[] =
{
    { "skip-phys-sort", no_argument, &skip_phys_sort, 1 },
    { "version",        no_argument, &print_version,  1 },
    { "help",           no_argument, &print_help,     1 },
    { 0, 0, 0, 0 }
};

static void
write_pack (const struct ca_cas_object *hashes, size_t hash_count)
{
  char tmp_path[32];

  struct pack_header *header;
  struct pack_entry *entries;
  off_t size;
  int pack_fd;

  size_t i;

  if (-1 == mkdir ("packs", 0777) && errno != EEXIST)
    err (EXIT_FAILURE, "mkdir failed");

  sprintf (tmp_path, "packs/pack.tmp.XXXXXX");

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

      sha1 = hashes[i].sha1;

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

      while (offset < entity_size
             && 0 < (ret = sendfile (pack_fd, entity_fd, &offset, entity_size - offset)))
        ;

      if (ret == -1)
        err (EXIT_FAILURE, "%s: sendfile failed", entity_path);
      else if (ret == 0 && entity_size > 0)
        errx (EXIT_FAILURE, "%s: sendfile unexpectedly returned 0", entity_path);

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

      if (-1 == link (tmp_path, path))
        {
          if (errno == EEXIST)
            continue;

          err (EXIT_FAILURE, "%s: link failed", path);
        }

      if (-1 == unlink (tmp_path))
        err (EXIT_FAILURE, "%s: failed to unlink", tmp_path);

      break;
    }
}

static int
phys_offset_cmp (const void *vlhs, const void *vrhs)
{
  const struct ca_cas_object *lhs = vlhs;
  const struct ca_cas_object *rhs = vrhs;

  /* Subtraction does not work, since phys_offset is usually bigger than int */

  if (lhs->phys_offset < rhs->phys_offset)
    return -1;

  if (lhs->phys_offset > rhs->phys_offset)
    return 1;

  return 0;
}

int
main (int argc, char **argv)
{
  struct ca_cas_object *objects = NULL;
  size_t object_count = 0;

  unsigned int scan_flags = CA_CAS_SCAN_FILES;
  int i;

  while ((i = getopt_long (argc, argv, "", long_options, 0)) != -1)
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
             "      --skip-phys-sort       do not sort files by physical offset before\n"
             "                               copying (this is the default on SSDs)\n"
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

  if (!skip_phys_sort && 0 != path_is_rotational ("."))
    scan_flags |= CA_CAS_INCLUDE_OFFSETS;

  if (-1 == scan_objects (&objects, &object_count, scan_flags))
    errx (EXIT_FAILURE, "scan_objects failed: %s", ca_cas_last_error ());

  if (!object_count)
    return EXIT_SUCCESS;

  if (0 != (scan_flags & CA_CAS_INCLUDE_OFFSETS))
    qsort (objects, object_count, sizeof (*objects), phys_offset_cmp);

  write_pack (objects, object_count);

  /* Now that the entities are in a synced .pack file, they can be removed */

  for (i = 0; i < object_count; ++i)
    {
      char entity_path[43];

      sha1_to_path (entity_path, objects[i].sha1);

      unlink (entity_path);
    }

  return EXIT_SUCCESS;
}
