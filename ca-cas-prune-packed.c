/*
    Content addressable storage redundant object pruning tool
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

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <err.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sysexits.h>
#include <unistd.h>

#include "ca-cas.h"
#include "ca-cas-internal.h"

static int do_dry_run;
static int print_version;
static int print_help;

static struct option long_options[] =
{
    { "dry-run",        no_argument, &do_dry_run,     1 },
    { "version",        no_argument, &print_version,  1 },
    { "help",           no_argument, &print_help,     1 },
    { 0, 0, 0, 0 }
};

static ssize_t pack_count;
static const struct ca_cas_pack_handle *packs;

static int
maybe_prune_object(struct ca_cas_object *object, void *arg)
{
  ssize_t pack_index;

  assert(!object->pack);

  for (pack_index = 0; pack_index < pack_count; ++pack_index)
    {
      const struct ca_cas_pack_handle *pack;
      char entity_path[43];
      uint64_t j;

      pack = &packs[pack_index];

      j = (uint64_t) object->sha1[0] << 56
        | (uint64_t) object->sha1[1] << 48
        | (uint64_t) object->sha1[2] << 40
        | (uint64_t) object->sha1[3] << 32
        | (uint64_t) object->sha1[4] << 24
        | (uint64_t) object->sha1[5] << 16
        | (uint64_t) object->sha1[6] << 8
        | (uint64_t) object->sha1[7];
      j %= pack->header->entry_count;

      while (pack->entries[j].offset)
        {
          if (!memcmp (pack->entries[j].sha1, object->sha1, 20))
            break;

          if (++j == pack->header->entry_count)
            j = 0;
        }

      if (!pack->entries[j].offset)
        continue;

      sha1_to_path (entity_path, object->sha1);

      if (do_dry_run)
        printf ("unlink %s\n", entity_path);
      else
        {
          if (-1 == unlink (entity_path))
            {
              fprintf (stderr, "Warning: Unlinking of %s failed: %s\n",
                       entity_path, strerror (errno));
            }
        }

      break;
    }

  return 0;
}

static void
prune_redundant_packs (void)
{
  const struct ca_cas_pack_handle *pack_i, *pack_j;
  size_t i, j, entry_index;
  unsigned char *removed;

  if (!(removed = calloc(1, pack_count)))
    err (EXIT_FAILURE, "calloc failed");

  for (i = 0; i < pack_count; ++i)
    {
      pack_i = &packs[i];

      /* Look for packs that completely contain pack_i.  */
      for (j = 0; j < pack_count; ++j)
        {
          if (i == j || removed[j])
            continue;

          fprintf(stderr, "%zu / %zu\n", i, j);

          pack_j = &packs[j];

          /* Only larger pack files can conceivably contain pack_i.  */
          if (pack_j->header->entry_count < pack_i->header->entry_count)
            continue;

          for (entry_index = 0; entry_index < pack_i->header->entry_count; ++entry_index)
            {
              const struct pack_entry *entry = &pack_i->entries[entry_index];
              uint64_t hash;

              if (!entry->offset)
                continue;

              hash = (uint64_t) entry->sha1[0] << 56
                | (uint64_t) entry->sha1[1] << 48
                | (uint64_t) entry->sha1[2] << 40
                | (uint64_t) entry->sha1[3] << 32
                | (uint64_t) entry->sha1[4] << 24
                | (uint64_t) entry->sha1[5] << 16
                | (uint64_t) entry->sha1[6] << 8
                | (uint64_t) entry->sha1[7];
              hash %= pack_j->header->entry_count;

              while (pack_j->entries[hash].offset)
                {
                  if (!memcmp(pack_j->entries[hash].sha1, entry->sha1, 20))
                    break;

                  if (++hash == pack_j->header->entry_count)
                    hash = 0;
                }

              /* Object not found; pack_j does not contain pack_i.  */
              if (!pack_j->entries[hash].offset)
                break;
            }

          if (entry_index == pack_i->header->entry_count)
            {
              assert (CA_cas_pack_dirfd >= 0);

              removed[i] = 1;

              if (-1 == unlinkat (CA_cas_pack_dirfd, pack_i->path, 0))
                {
                  fprintf (stderr, "Warning: Unlinking of %s failed: %s\n",
                           pack_i->path, strerror (errno));
                }

              break;
            }
        }
    }
}

int
main (int argc, char **argv)
{
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
      printf ("Usage: %s [OPTION]... [ROOT]\n"
             "\n"
             "      --dry-run              don't actually remove any objects, only show\n"
             "                               those that would have been removed\n"
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

  if (-1 == (pack_count = CA_cas_pack_get_handles (&packs)))
    {
      errx (EXIT_FAILURE, "error opening pack files: %s", ca_cas_last_error ());

      return -1;
    }

  if (-1 == scan_objects (maybe_prune_object, CA_CAS_SCAN_FILES, NULL))
    errx (EXIT_FAILURE, "scan_objects failed: %s", ca_cas_last_error ());

  prune_redundant_packs ();

  return EXIT_SUCCESS;
}
