#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "aws.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "sha256.h"
#include "ca-cas-internal.h"

#define AWS_SIGNATURE_ALGORITHM "AWS4-HMAC-SHA256"

static const char *empty_sha256_hex =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

static int cmpstringp(const void *p1, const void *p2) {
  return strcmp(*(char *const *)p1, *(char *const *)p2);
}

static int add_header(struct curl_slist **headers, const char *header) {
  struct curl_slist *new_headers;

  if (!(new_headers = curl_slist_append(*headers, header))) return -1;

  *headers = new_headers;

  return 0;
}

int aws_sign_request(char signature[static AWS_SIGNATURE_SIZE],
                     char **signed_headers, const char *method,
                     const char *path, const char *query,
                     struct curl_slist **headers,
                     const char *payload_sha256_hex, const char *secret_key,
                     const char *date, const char *region,
                     const char *service) {
  static const char *timestamp_header = "x-amz-date";
  static const char *termination_string = "aws4_request";

  unsigned char hash[32], key[32];
  struct curl_slist *header;
  struct sha256_context sha256;
  const char *timestamp = NULL;

  size_t secret_length;
  char *secret_buffer = NULL;

  size_t header_idx = 0, header_count = 0;
  size_t header_names_length = 0;
  char **sorted_headers = NULL;

  int result = -1;

  *signed_headers = NULL;

  /* Canonicalize headers by converting keys to lower case and collapsing all
   * meaningless whitespace into a single SPACE character.  */
  for (header = *headers; header; header = header->next, ++header_count) {
    char *o, *i = header->data;
    int in_quotes = 0;

    while (*i && *i != ':') {
      *i = tolower(*i);
      ++i;
    }

    if (!*i) {
      assert(!"Header must contain ':'");
      errno = EINVAL;

      goto out;
    }

    if (i - header->data == strlen(timestamp_header) &&
        !memcmp(header->data, timestamp_header, i - header->data)) {
      timestamp = i + 1;
    }

    header_names_length += (i - header->data);

    o = ++i; /* Skip ':'.  */

    while (*i && isspace(*i)) ++i;

    while (*i) {
      if (!in_quotes && isspace(*i)) {
        if (o[-1] != ' ') *o++ = ' ';
      } else {
        if (*i == '"') in_quotes = !in_quotes;

        *o++ = *i++;
      }
    }

    *o = 0;
  }

  if (!timestamp) {
    assert(!"Request must have timestamp header");
    errno = EINVAL;

    goto out;
  }

  if (!(sorted_headers = calloc(sizeof(*sorted_headers), header_count)))
    goto out;

  for (header = *headers; header; header = header->next)
    sorted_headers[header_idx++] = header->data;

  qsort(sorted_headers, header_count, sizeof(*sorted_headers), cmpstringp);

  if (!(*signed_headers = malloc(header_names_length + header_count))) goto out;

  (*signed_headers)[0] = 0;

  for (header_idx = 0; header_idx < header_count; ++header_idx) {
    const char *header = sorted_headers[header_idx];
    char *colon;

    if (header_idx > 0) strcat(*signed_headers, ";");

    /* We have already asserted that the ':' exists.  */
    colon = strchr(header, ':');

    strncat(*signed_headers, header, colon - header);
  }

  sha256_init(&sha256);
  sha256_add(&sha256, method, strlen(method));
  sha256_add(&sha256, "\n", 1);
  sha256_add(&sha256, path, strlen(path));
  sha256_add(&sha256, "\n", 1);
  sha256_add(&sha256, query, strlen(query));
  sha256_add(&sha256, "\n", 1);

  for (header_idx = 0; header_idx < header_count; ++header_idx) {
    const char *header = sorted_headers[header_idx];
    sha256_add(&sha256, header, strlen(header));
    sha256_add(&sha256, "\n", 1);
  }

  sha256_add(&sha256, "\n", 1);
  sha256_add(&sha256, *signed_headers, header_names_length + header_count - 1);
  sha256_add(&sha256, "\n", 1);
  sha256_add(&sha256, payload_sha256_hex, strlen(payload_sha256_hex));

  sha256_finish(&sha256, hash);

  /* Finish producing the hash of the canonical request, which will serve as an
   * input to the next step.  */
  binary_to_hex(signature, hash, sizeof(hash));

  secret_length = strlen(secret_key);
  if (!(secret_buffer = malloc(secret_length + 4))) goto out;
  memcpy(secret_buffer, "AWS4", 4);
  memcpy(secret_buffer + 4, secret_key, secret_length);

  sha256_hmac(key, secret_buffer, secret_length + 4, date, strlen(date));
  sha256_hmac(key, key, sizeof(key), region, strlen(region));
  sha256_hmac(key, key, sizeof(key), service, strlen(service));
  sha256_hmac(key, key, sizeof(key), termination_string,
              strlen(termination_string));

  sha256_hmac_init(&sha256, key, sizeof(key));
  sha256_add(&sha256, AWS_SIGNATURE_ALGORITHM "\n",
             strlen(AWS_SIGNATURE_ALGORITHM "\n"));
  sha256_add(&sha256, timestamp, strlen(timestamp));
  sha256_add(&sha256, "\n", 1);
  sha256_add(&sha256, date, strlen(date));
  sha256_add(&sha256, "/", 1);
  sha256_add(&sha256, region, strlen(region));
  sha256_add(&sha256, "/", 1);
  sha256_add(&sha256, service, strlen(service));
  sha256_add(&sha256, "/", 1);
  sha256_add(&sha256, termination_string, strlen(termination_string));
  sha256_add(&sha256, "\n", 1);
  sha256_add(&sha256, signature, AWS_SIGNATURE_SIZE);
  sha256_hmac_finish(&sha256, key, sizeof(key), hash);

  binary_to_hex(signature, hash, sizeof(hash));

  result = 0;

out:

  if (result == -1) free(*signed_headers);

  free(secret_buffer);
  free(sorted_headers);

  return result;
}

int aws_setup_request(CURL *curl, const char *method, const char *path,
                      const char *query, struct curl_slist **headers,
                      const char *payload_sha256_hex, const char *access_key,
                      const char *secret_key, const char *region,
                      const char *service) {
  char *url = NULL;
  char *signed_headers = NULL;
  char *host_header = NULL;
  char *authorization_header = NULL;
  char signature[AWS_SIGNATURE_SIZE];

  time_t now;
  struct tm now_tm;
  char date[9], date_header[32];

  int result = -1;

  if (-1 == asprintf(&url, "https://%s.%s.amazonaws.com%s%s%s", service, region,
                     path, *query ? "?" : "", query))
    goto out;

  curl_easy_setopt(curl, CURLOPT_URL, url);

  now = time(0);
  now_tm = *gmtime(&now);

  strftime(date, sizeof(date), "%Y%m%d", &now_tm);
  strftime(date_header, sizeof(date_header), "x-amz-date:%Y%m%dT%H%M%SZ",
           &now_tm);

  if (-1 == add_header(headers, date_header)) goto out;

  if (-1 == asprintf(&host_header, "host:%s.%s.amazonaws.com", service, region))
    goto out;

  if (-1 == add_header(headers, host_header)) goto out;

  if (-1 == aws_sign_request(signature, &signed_headers, method, path, query,
                             headers, payload_sha256_hex, secret_key, date,
                             region, service))
    goto out;

  if (-1 == asprintf(&authorization_header,
                     "Authorization: " AWS_SIGNATURE_ALGORITHM
                     " "
                     "Credential=%s/%s/%s/%s/aws4_request,"
                     "SignedHeaders=%s,"
                     "Signature=%.*s",
                     access_key, date, region, service, signed_headers,
                     (int)AWS_SIGNATURE_SIZE, signature))
    goto out;

  if (-1 == add_header(headers, authorization_header)) goto out;

  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, *headers);

  result = 0;

out:

  free(authorization_header);
  free(signed_headers);
  free(host_header);
  free(url);

  return result;
}

int aws_glacier_get_vaults(CURL *curl, struct curl_slist **headers,
                           const char *access_key, const char *secret_key,
                           const char *region) {
  if (-1 == add_header(headers, "x-amz-glacier-version:2012-06-01")) return -1;

  return aws_setup_request(curl, "GET", "/-/vaults", "", headers,
                           empty_sha256_hex, access_key, secret_key, region,
                           "glacier");
}
