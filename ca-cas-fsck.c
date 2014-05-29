/*
    Content addressable storage integrity checker
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
#include "config.h"
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
#include "sha1.h"

static int skip_objects;
static int skip_sha1;
static int print_version;
static int print_help;

static struct option long_options[] = {
    {"skip-objects", no_argument, &skip_objects, 1},
    {"skip-sha1", no_argument, &skip_sha1, 1},
    {"version", no_argument, &print_version, 1},
    {"help", no_argument, &print_help, 1},
    {0, 0, 0, 0}};

static int broken;

static int check_object(struct ca_cas_object *object, void *arg) {
  char buffer[65536];
  char entity_path[43];
  unsigned char got_sha1[20];
  int entity_fd;

  int ret = 0;
  off_t offset = 0, entity_size;

  struct sha1_context sha1;

  sha1_to_path(entity_path, object->sha1);

  if (-1 == (entity_fd = open(entity_path, O_RDONLY)))
    err(EXIT_FAILURE, "%s: open failed", entity_path);

  if (-1 == (entity_size = lseek(entity_fd, 0, SEEK_END)))
    err(EXIT_FAILURE, "%s: failed to seek to end of file", entity_path);

  sha1_init(&sha1);

  while (offset < entity_size) {
    size_t amount = entity_size - offset;

    if (amount > sizeof(buffer)) amount = sizeof(buffer);

    if (0 < (ret = read(entity_fd, buffer, amount))) {
      if (ret == -1)
        err(EXIT_FAILURE, "%s: read failed", entity_path);
      else if (ret == 0 && entity_size > 0)
        errx(EXIT_FAILURE, "%s: read unexpectedly returned 0", entity_path);
    }

    sha1_add(&sha1, buffer, ret);

    offset += ret;
  }

  close(entity_fd);

  sha1_finish(&sha1, got_sha1);

  if (memcmp(got_sha1, object->sha1, 20)) {
    char expected_hex[41], got_hex[41];

    ca_cas_sha1_to_hex(object->sha1, expected_hex);
    ca_cas_sha1_to_hex(got_sha1, got_hex);

    printf("%s: unexpected SHA-1 sum %s, expected %s\n", entity_path, got_hex,
           expected_hex);

    broken = 1;
  }

  return 0;
}

/* Compares to pack_entry objects by offset.  */
static int entrycmp(const void *vlhs, const void *vrhs) {
  struct pack_entry *const *lhs = vlhs;
  struct pack_entry *const *rhs = vrhs;

  if ((*lhs)->offset < (*rhs)->offset)
    return -1;
  else
    return 1;
}

/* Sorts a list of pack_entry objects by their offset, then checks their SHA-1
   digests.  */
static void flush_entries(const struct ca_cas_pack_handle *pack,
                          const struct pack_entry **entries, size_t count) {
  size_t i;

  qsort(entries, count, sizeof(entries), entrycmp);

  for (i = 0; i < count; ++i) {
    const struct pack_entry *entry = entries[i];
    struct sha1_context sha1;
    unsigned char got_sha1[20];

    sha1_init(&sha1);
    sha1_add(&sha1, &pack->data[entry->offset], entry->size);
    sha1_finish(&sha1, got_sha1);

    if (memcmp(got_sha1, entry->sha1, 20)) {
      char expected_hex[41], got_hex[41];

      ca_cas_sha1_to_hex(entry->sha1, expected_hex);
      ca_cas_sha1_to_hex(got_sha1, got_hex);

      printf("%s: unexpected SHA-1 sum %s, expected %s\n", pack->path, got_hex,
             expected_hex);

      broken = 1;
    }
  }
}

static void check_packs(void) {
  ssize_t pack_count;
  const struct ca_cas_pack_handle *packs;

  const struct ca_cas_pack_handle *pack;
  size_t i, entry_index;

  if (-1 == (pack_count = CA_cas_pack_get_handles(&packs)))
    errx(EXIT_FAILURE, "error opening pack files: %s", ca_cas_last_error());

  /* In the first pass, we do simple sanity checks.  */
  for (i = 0; i < pack_count; ++i) {
    pack = &packs[i];

    size_t sum_size = 0;

    for (entry_index = 0; entry_index < pack->header->entry_count;
         ++entry_index) {
      const struct pack_entry *entry = &pack->entries[entry_index];

      if (!entry->offset) continue;

      if (entry->offset < pack->data_start) {
        printf("%s item %zu: first byte is inside pack file header\n",
               pack->path, entry_index);

        broken = 1;

        break;
      } else if (entry->offset + entry->size > pack->size) {
        printf("%s item %zu: entry extends past end-of-file\n", pack->path,
               entry_index);

        broken = 1;

        break;
      }

      sum_size += entry->size;
    }

    /* Verify that the total size of the entries in the pack file corresponds
     * to the size of the pack file.  */
    if (sum_size + pack->data_start != pack->size) {
      printf("%s: unexpected pack file size %zu, expected %zu\n", pack->path,
             pack->size, sum_size + pack->data_start);

      broken = 1;
    }
  }

  /* In the second pass, we actually verify the SHA-1 digests.  */
  if (!skip_sha1) {
    static const size_t BUFFER_SIZE = 1024 * 1024;
    const struct pack_entry **buffer;
    buffer = calloc(sizeof(*buffer), BUFFER_SIZE);

    for (i = 0; i < pack_count; ++i) {
      size_t buffer_fill = 0;

      pack = &packs[i];

      for (entry_index = 0; entry_index < pack->header->entry_count;
           ++entry_index) {
        const struct pack_entry *entry = &pack->entries[entry_index];

        if (!entry->offset) continue;

        buffer[buffer_fill++] = entry;

        if (buffer_fill == BUFFER_SIZE) {
          flush_entries(pack, buffer, buffer_fill);
          buffer_fill = 0;
        }
      }

      flush_entries(pack, buffer, buffer_fill);
    }

    free(buffer);
  }
}

int main(int argc, char **argv) {
  int i;

  while ((i = getopt_long(argc, argv, "", long_options, 0)) != -1) {
    switch (i) {
      case 0:

        break;

      case '?':

        errx(EX_USAGE, "Try '%s --help' for more information.", argv[0]);
    }
  }

  if (print_help) {
    printf(
        "Usage: %s [OPTION]... [ROOT]\n"
        "\n"
        "      --skip-objects         only process pack files\n"
        "      --skip-sha1            do not verify SHA-1 digest\n"
        "      --help     display this help and exit\n"
        "      --version  display version information and exit\n"
        "\n"
        "Report bugs to <morten.hustveit@gmail.com>\n",
        argv[0]);

    return EXIT_SUCCESS;
  }

  if (print_version) {
    fprintf(stdout, "%s\n", PACKAGE_STRING);

    return EXIT_SUCCESS;
  }

  if (optind + 1 == argc) {
    if (-1 == chdir(argv[optind]))
      err(EXIT_FAILURE, "Unable to chdir to '%s'", argv[optind]);
  } else if (optind + 1 < argc)
    errx(EX_USAGE, "Usage: %s [OPTION]... [PATH]", argv[0]);

  if (skip_sha1) skip_objects = 1;

  if (!skip_objects &&
      -1 == scan_objects(check_object, CA_CAS_SCAN_FILES, NULL))
    errx(EXIT_FAILURE, "scan_objects failed: %s", ca_cas_last_error());

  check_packs();

  return broken ? EXIT_FAILURE : EXIT_SUCCESS;
}
