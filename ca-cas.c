/*
    Content addressable storage tool
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

#include "sha1.h"
#include "ca-cas-internal.h"

static int print_version;
static int print_help;
static int do_fsync = 1;

static struct option long_options[] =
{
    { "command",  required_argument, NULL,           'c' },
    { "no-fsync",       no_argument, &do_fsync,      0 },
    { "version",        no_argument, &print_version, 1 },
    { "help",           no_argument, &print_help,    1 },
    { 0, 0, 0, 0 }
};

static int
parse_sha1_hex (unsigned char sha1[static 20], const char *string)
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

  for (i = 0; i < 40; i += 2, string += 2)
    {
      if (!isxdigit (string[0]) || !isxdigit (string[1]))
        return -1;

      /* Works with both upper- and lower-case */
      *out++ = (helper[string[0] & 0x1f] << 4)
             | (helper[string[1] & 0x1f]);
    }

  /* Verify no garbage after end of SHA-1 */
  if (*string)
    return -1;

  return 0;
}

static int
lookup (const unsigned char sha1[static 20], int retrieve)
{
  char path[43];

  int fd;
  ssize_t ret = 0;
  off_t offset = 0, end;

  struct dirent *ent;
  int dirfd;
  DIR *dir = NULL;

  sha1_to_path (path, sha1);

  /* Look in files first to prevent race conditions;  ca-cas-repack will
   * completely finalize an archive before removing its constituent files, so
   * an existing item is guaranteed to be in an archive if it isn't in a file.
   * The converse isn't true.  */

  if (!retrieve)
    {
      if (0 == access (path, F_OK))
        return 0;
    }
  else
    {
      if (-1 != (fd = open (path, O_RDONLY)))
        {
          if (-1 == (end = lseek (fd, 0, SEEK_END))
              || -1 == lseek (fd, 0, SEEK_SET))
            {
              printf ("500 lseek failed: %s\n", strerror (errno));

              close (fd);

              return -1;
            }

          printf ("200 %lld\n", (long long) end);
          fflush (stdout);

          while (offset < end
                 && -1 != (ret = sendfile (STDOUT_FILENO, fd, NULL, end - offset)))
            offset += ret;

          close (fd);

          return (ret >= 0) ? 0 : -1;
        }
    }

  if (errno != ENOENT && errno != ENOTDIR)
    {
      printf ("500 open failed: %s\n", strerror (errno));

      return -1;
    }

  if (-1 == (dirfd = open ("packs", O_DIRECTORY | O_RDONLY)))
    {
      printf ("500 open \"packs\" directory: %s\n", strerror (errno));

      return -1;
    }

  if (!(dir = fdopendir (dirfd)))
    {
      printf ("500 opendir failed: %s\n", strerror (errno));

      close (dirfd);

      return -1;
    }

  for (;;)
    {
      const char *extension;

      off_t pack_size;

      const uint8_t *map = MAP_FAILED;
      const struct pack_header *header;
      const struct pack_entry *entries;
      uint64_t j, data_start;

      int ok = 0;

      errno = 0;

      if (!(ent = readdir (dir)))
        {
          if (!errno)
            goto not_found;

          printf ("500 readdir failed: %s\n", strerror (errno));
        }

      if (ent->d_name[0] == '.'
          || !(extension = strrchr (ent->d_name, '.'))
          || strcmp (extension, ".pack"))
        continue;

      if (-1 == (fd = openat (dirfd, ent->d_name, O_RDONLY)))
        break;

      if (-1 == (pack_size = lseek (fd, 0, SEEK_END)))
        goto fail;

      if (pack_size < sizeof (*header))
        {
          errno = EINVAL;

          goto fail;
        }

      if (MAP_FAILED == (map = mmap (NULL, pack_size, PROT_READ, MAP_SHARED, fd, 0)))
        {
          close (fd);

          goto fail;
        }

      close (fd);

      header = (const struct pack_header *) map;
      data_start = sizeof (*header) + header->entry_count * sizeof (*entries);

      if (header->magic != PACK_MAGIC || data_start > pack_size)
        {
          errno = EINVAL;

          goto fail;
        }

      entries = (const struct pack_entry *) (map + sizeof (*header));

      j = (uint64_t) sha1[0] << 56
        | (uint64_t) sha1[1] << 48
        | (uint64_t) sha1[2] << 40
        | (uint64_t) sha1[3] << 32
        | (uint64_t) sha1[4] << 24
        | (uint64_t) sha1[5] << 16
        | (uint64_t) sha1[6] << 8
        | (uint64_t) sha1[7];
      j %= header->entry_count;

      for (;;)
        {
          if (!entries[j].offset)
            goto next;

          if (!memcmp (entries[j].sha1, sha1, 20))
            break;

          if (++j == header->entry_count)
            j = 0;
        }

      /* Found match.  Now write it to stdout */

      offset = entries[j].offset;
      end = offset + entries[j].size;

      if (offset < data_start || end > pack_size)
        {
          errno = EINVAL;

          goto fail;
        }

      printf ("200 %lld\n", (long long) (end - offset));

      while (offset < end
             && -1 != (ret = fwrite (map + offset, 1, end - offset, stdout)))
        offset += ret;

      if (-1 == ret)
        goto fail;

      ok = 1;

next:
      munmap ((void *) map, pack_size);

      if (ok)
        return 0;

      continue;

fail:
      if (map != MAP_FAILED)
        munmap ((void *) map, pack_size);

      printf ("500 Lookup failed: %s\n", strerror (errno));

      return -1;
    }

not_found:

  if (dir)
    closedir (dir);

  errno = ENOENT;

  printf ("404 Entity not found\n");

  return -1;
}

static int
pmkdir (unsigned char dir_0, unsigned char dir_1)
{
  static uint32_t existing_dirs_0[256 / 32];
  static uint32_t existing_dirs_1[65536 / 32];

  uint16_t subdir;
  char path[6];

  if (0 == (existing_dirs_0[dir_0 >> 5] & (1 << (dir_0 & 0x1f))))
    {
      sprintf (path, "%02x", dir_0);

      if (-1 == mkdir (path, 0777) && errno != EEXIST)
        return -1;

      existing_dirs_0[dir_0 >> 5] |= (1 << (dir_0 & 0x1f));
    }

  subdir = (dir_0 << 8) | dir_1;

  if (0 == (existing_dirs_1[subdir >> 5] & (1 << (subdir & 0x1f))))
    {
      sprintf (path, "%02x/%02x", dir_0, dir_1);

      if (-1 == mkdir (path, 0777) && errno != EEXIST)
        return -1;

      existing_dirs_1[subdir >> 5] |= (1 << (subdir & 0x1f));
    }

  return 0;
}

static void
store (long long size)
{
  char buffer[65536];
  char tmp_path[11], output_path[43];
  unsigned char sha1_digest[20];
  long long offset = 0;
  ssize_t ret;
  int fd;

  struct sha1_context sha1;

  sha1_init (&sha1);

  sprintf (tmp_path, "tmp.XXXXXX");

  if (-1 == (fd = mkstemp (tmp_path)))
    {
      printf ("500 mkstemp failed: %s\n", strerror (errno));

      goto done;
    }

  while ((size == -1 && !feof (stdin)) || offset < size)
    {
      size_t amount;
      long long write_offset;

      if (size == -1)
        amount = sizeof (buffer);
      else
        {
          amount = size - offset;

          if (amount > sizeof (buffer))
            amount = sizeof (buffer);
        }

      ret = fread (buffer, 1, amount, stdin);

      if (ret <= 0)
        {
          if (ret == -1)
            {
              if (errno == EINTR)
                continue;

              printf ("500 read failed: %s\n", strerror (errno));
            }
          else if (size == -1)
            break;
          else
            printf ("500 short read\n");

          goto done;
        }

      amount = ret;
      offset += amount;

      sha1_add (&sha1, buffer, amount);

      write_offset = 0;

      while (write_offset < amount)
        {
          ret = write (fd, &buffer[write_offset], amount - write_offset);

          if (ret <= 0)
            {
              if (ret == -1)
                {
                  if (errno == EINTR)
                    continue;

                  printf ("500 write failed: %s\n", strerror (errno));
                }
              else
                printf ("500 short write\n");

              goto done;
            }

          write_offset += ret;
        }
    }

  sha1_finish (&sha1, sha1_digest);

  sha1_to_path (output_path, sha1_digest);

  if (-1 == access (output_path, F_OK))
    {
      if (-1 == pmkdir (sha1_digest[0], sha1_digest[1]))
        {
          printf ("500 mkdir failed: %s\n", strerror (errno));

          goto done;
        }

      if (do_fsync && -1 == fsync (fd))
        {
          printf ("500 fsync failed: %s\n", strerror (errno));

          goto done;
        }

      if (-1 == rename (tmp_path, output_path))
        {
          printf ("500 rename failed: %s\n", strerror (errno));

          goto done;
        }

      /* fsync succeeded, so we don't care about the result of close */
      (void) close (fd);
      fd = -1;
    }

  printf ("201 %.2s%.2s%s\n", output_path, output_path + 3, output_path + 6);

done:

  if (size == -1)
    close (STDIN_FILENO);

  if (fd != -1)
    {
      unlink (tmp_path);
      close (fd);
    }
}

static void
do_command (const char *command)
{
  unsigned char sha1[20];
  long long size;
  char *ch;

  if (!strcmp (command, "PUT"))
    store (-1);
  else if (!strncmp (command, "PUT ", strlen ("PUT ")))
    {
      size = strtoll (command + strlen ("PUT "), &ch, 10);

      if (size < 0 || *ch != 0)
        {
          printf ("400 Invalid PUT request.  Expected PUT [LENGTH]\n");

          return;
        }

      store (size);
    }
  else if (!strncmp (command, "GET ", strlen ("GET ")))
    {
      if (-1 == parse_sha1_hex (sha1, command + strlen ("GET ")))
        {
          printf ("400 Invalid GET request.  Expected GET <HEXADECIMAL SHA-1>\n");

          return;
        }

      lookup (sha1, 1);
    }
  else if (!strncmp (command, "HEAD ", strlen ("HEAD ")))
    {
      if (-1 == parse_sha1_hex (sha1, command + strlen ("HEAD ")))
        {
          printf ("400 Invalid HEAD request.  Expected HEAD <HEXADECIMAL SHA-1>\n");

          return;
        }

      if (0 == lookup (sha1, 0))
        printf ("200 Entity exists\n");
    }
  else
    printf ("405 Unknown command\n");
}

int
main (int argc, char **argv)
{
  const char *command = NULL;
  char line[128];
  int i;

  while ((i = getopt_long (argc, argv, "c:", long_options, 0)) != -1)
    {
      switch (i)
        {
        case 0:

          break;

        case 'c':

          command = optarg;

          break;

        case '?':

          errx (EX_USAGE, "Try '%s --help' for more information.", argv[0]);
        }
    }

  if (print_help)
    {
      printf ("Usage: %s [OPTION]...\n"
             "\n"
             "  -c, --command=STRING       execute commands in STRING and exit\n"
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
        err (EXIT_FAILURE, "Unable to chdir to '%s': %s", argv[optind], strerror (errno));
    }
  else if (optind + 1 < argc)
    errx (EX_USAGE, "Usage: %s [OPTION]... [PATH]", argv[0]);

  if (command)
    do_command (command);
  else
    {
      line[sizeof(line) - 1] = 0;

      while (NULL != fgets (line, sizeof (line), stdin))
        {
          size_t line_length;

          line_length = strlen (line);

          /* No valid commands are this long anyway */
          if (line_length && line[line_length - 1] != '\n')
            errx (EXIT_FAILURE, "Input line too long");

          while (line_length && isspace (line[line_length - 1]))
            --line_length;

          if (!line_length)
            continue;

          line[line_length] = 0;

          do_command (line);

          fflush (stdout);
        }
    }

  return EXIT_SUCCESS;
}
