#include <curl/curl.h>

#define AWS_SIGNATURE_SIZE 64

/* Signs a request to AWS.
 * Modifies the `headers' parameter.  */
int
aws_sign_request (char signature[static AWS_SIGNATURE_SIZE],
                  char **signed_headers,
                  const char *method, const char *path, const char *query,
                  struct curl_slist **headers, const char *payload_sha256_hex,
                  const char *secret_key, const char *date, const char *region,
                  const char *service);

/* Configures a CURL handle for a given AWS request.
 * Modifies the `headers' parameter.  */
int
aws_setup_request (CURL *curl,
                   const char *method, const char *path, const char *query,
                   struct curl_slist **headers, const char *payload_sha256_hex,
                   const char *access_key, const char *secret_key,
                   const char *region, const char *service);

int
aws_glacier_get_vaults (CURL *curl, struct curl_slist **headers,
                        const char *access_key, const char *secret_key,
                        const char *region);
