#include <stdint.h>
#include <stdlib.h>

#define PACK_MAGIC 0x63617350

struct ca_cas_object {
  const struct ca_cas_pack_handle *pack;
  off_t phys_offset;
  unsigned char sha1[20];
};

struct pack_header {
  uint64_t magic;
  uint64_t entry_count;
};

/* 32 bytes */
struct pack_entry {
  uint64_t offset;
  uint32_t size;
  unsigned char sha1[20];
};

struct ca_cas_pack_handle {
  char *path;
  const char *data;
  size_t data_start;
  size_t size;
  const struct pack_header *header;
  const struct pack_entry *entries;
};

enum ca_cas_scan_flags {
  CA_CAS_SCAN_FILES = 0x0001,
  CA_CAS_SCAN_PACKS = 0x0002,
  CA_CAS_INCLUDE_OFFSETS = 0x0004,
};

void sha1_to_path(char path[static 43], const unsigned char sha1[static 20]);

void binary_to_hex(char *output, const unsigned char *input, size_t size);

int path_is_rotational(const char *path);

int get_objects(struct ca_cas_object **ret_objects, size_t *ret_object_count,
                unsigned int flags);

int scan_objects(int (*callback)(struct ca_cas_object *object, void *arg),
                 unsigned int flags, void *arg);

ssize_t CA_cas_pack_get_handles(const struct ca_cas_pack_handle **handles);

extern int CA_cas_pack_dirfd;
