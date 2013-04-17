void
sha1_to_path (char path[static 43], const unsigned char sha1[static 20])
{
  static const char hex[] = "0123456789abcdef";
  unsigned int i;

  path[0] = hex[sha1[0] >> 4];
  path[1] = hex[sha1[0] & 15];
  path[2] = '/';
  path[3] = hex[sha1[1] >> 4];
  path[4] = hex[sha1[1] & 15];
  path[5] = '/';

  for (i = 2; i < 20; ++i)
    {
      path[i * 2 + 2] = hex[sha1[i] >> 4];
      path[i * 2 + 3] = hex[sha1[i] & 15];

      /* 19 * 2 + 3 == 41 */
    }

  path[42] = 0;
}
