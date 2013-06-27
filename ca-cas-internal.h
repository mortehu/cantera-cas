#include <stdint.h>
#include <stdlib.h>

#define PACK_MAGIC 0x63617350

struct ca_cas_object
{
  off_t phys_offset;
  uint32_t pack;
  unsigned char sha1[20];
};

struct pack_header
{
  uint64_t magic;
  uint64_t entry_count;
};

/* 32 bytes */
struct pack_entry
{
  uint64_t offset;
  uint32_t size;
  unsigned char sha1[20];
};

void
sha1_to_path (char path[static 43], const unsigned char sha1[static 20]);

void
binary_to_hex (char *output, const unsigned char *input, size_t size);

int
path_is_rotational (const char *path);

enum ca_cas_scan_flags
{
  CA_CAS_SCAN_FILES =           0x0001,
  CA_CAS_SCAN_PACKS =           0x0002,
  CA_CAS_INCLUDE_OFFSETS = 0x0004
};

int
scan_objects (struct ca_cas_object **ret_objects, size_t *ret_object_count,
              unsigned int flags);
