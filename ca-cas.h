#ifndef CA_CAS_H_
#define CA_CAS_H_ 1

#include <stdlib.h>

struct ca_cas_context;

/*****************************************************************************/

const char *
ca_cas_last_error (void);

void
ca_cas_clear_error (void);

void
ca_cas_set_error (const char *format, ...);

/*****************************************************************************/

struct ca_cas_context *
ca_cas_connect (const char *hostname);

void
ca_cas_free (struct ca_cas_context *ctx);

ssize_t
ca_cas_get (struct ca_cas_context *ctx,
            const unsigned char sha1[static 20], void **data);

int
ca_cas_put (struct ca_cas_context *ctx,
            unsigned char sha1[static 20], const void *data, size_t size);

void
ca_cas_sha1_to_hex (const unsigned char sha1[static 20], char hex[static 41]);

int
ca_cas_hex_to_sha1 (unsigned char sha1[static 20], const char *hex);

#endif /* !CA_CAS_H_ */
