#ifndef CA_CAS_H_
#define CA_CAS_H_ 1

#include <stdint.h>

#define PACK_MAGIC 0x63617350

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

#endif /* !CA_CAS_H_ */
