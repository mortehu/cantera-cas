#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aws.h"

static void
check_signature (void)
{
  struct curl_slist *headers = NULL;
  char signature[AWS_SIGNATURE_SIZE + 1];
  char *signed_headers;

  /* Headers not in alphabetical order so that we can verify that
   * aws_sign_request sorts them before signing.  */
  headers = curl_slist_append (headers, "X-AMZ-Date: 20120525T002453Z");
  headers = curl_slist_append (headers, "X-AMZ-Glacier-Version: 2012-06-01");
  headers = curl_slist_append (headers, "Host: glacier.us-east-1.amazonaws.com");

  aws_sign_request (signature, &signed_headers,
                    "PUT", "/-/vaults/examplevault", "", &headers,
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    "20120525", "us-east-1", "glacier");

  signature[AWS_SIGNATURE_SIZE] = 0;

  assert (!strcmp (signature, "3ce5b2f2fffac9262b4da9256f8d086b4aaf42eba5f111c21681a65a127b7c2a"));
  assert (!strcmp (signed_headers, "host;x-amz-date;x-amz-glacier-version"));

  free (signed_headers);
  curl_slist_free_all (headers);
}

int
main (int argc, char **argv)
{
  check_signature ();

  return EXIT_SUCCESS;
}
