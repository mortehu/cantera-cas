#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

#include <err.h>
#include <getopt.h>
#include <sysexits.h>

#include <curl/curl.h>
#include <curl/easy.h>

#include "aws.h"

static int print_version;
static int print_help;
static const char *access_key;
static const char *secret_key;
static const char *region;

static struct option long_options[] =
{
    { "access-key",  required_argument, NULL,           'a' },
    { "secret-key",  required_argument, NULL,           's' },
    { "region",      required_argument, NULL,           'r' },
    { "version",           no_argument, &print_version, 1 },
    { "help",              no_argument, &print_help,    1 },
    { 0, 0, 0, 0 }
};


int
main (int argc, char **argv)
{
  struct curl_slist *headers = NULL;
  CURL* curl = NULL;
  CURLcode curl_error;

  int i;

  access_key = getenv ("AWS_ACCESS_KEY_ID");
  secret_key = getenv ("AWS_SECRET_ACCESS_KEY");
  region = getenv ("AWS_GLACIER_REGION");

  while ((i = getopt_long (argc, argv, "", long_options, 0)) != -1)
    {
      switch (i)
        {
        case 0:

          break;

        case 'a': access_key = optarg; break;
        case 's': secret_key = optarg; break;
        case 'r': region = optarg; break;

        case '?':

          errx (EX_USAGE, "Try '%s --help' for more information.", argv[0]);
        }
    }

  if (print_help)
    {
      printf ("Usage: %s [OPTION]...\n"
             "\n"
             "      --access-key=KEY       set AWS access key\n"
             "      --secret-key=KEY       set AWS secret key\n"
             "      --region=REGION        set AWS region (us-west-1, us-west-2, us-east-1,"
             "                                             eu-west-1, ap-northeast-1)\n"
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

  if (!access_key || !secret_key || !region)
    {
      if (!access_key)
        fprintf (stderr, "AWS access key is missing.  Set using --access-key or AWS_ACCESS_KEY_ID\n");

      if (!secret_key)
        fprintf (stderr, "AWS secret key is missing,  Set using --secret-key or AWS_SECRET_ACCESS_KEY\n");

      if (!region)
        fprintf (stderr, "AWS region is missing.  Set using --region or AWS_GLACIER_REGION\n");

      errx (EX_USAGE, "Try '%s --help' for more information.", argv[0]);
    }

  if (!(curl = curl_easy_init()))
    errx (EXIT_FAILURE, "curl_easy_init returned NULL");

  if (-1 == aws_glacier_get_vaults (curl, &headers, access_key, secret_key, region))
    err (EXIT_FAILURE, "aws_glacier_get_vaults failed");

  curl_easy_setopt (curl, CURLOPT_USERAGENT, PACKAGE_NAME "/" VERSION);
  curl_easy_setopt (curl, CURLOPT_WRITEDATA, stdout);
  curl_easy_setopt (curl, CURLOPT_NOSIGNAL, 1);

  if (0 != (curl_error = curl_easy_perform (curl)))
    errx (EXIT_FAILURE, "curl_easy_perform failed: %s", curl_easy_strerror (curl_error));

  putchar ('\n');

  curl_slist_free_all (headers);

  curl_easy_cleanup (curl);

  return EXIT_SUCCESS;
}
