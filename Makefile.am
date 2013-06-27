noinst_LIBRARIES = libca-cas-internal.a libca-aws.a
lib_LIBRARIES = libca-cas.a
include_HEADERS = ca-cas.h
bin_PROGRAMS = \
  ca-cas \
  ca-cas-amazon-glacier \
  ca-cas-repack

ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = -I.
AM_CFLAGS = -Wall -Werror -g -fPIC $(PACKAGES_CFLAGS)

libca_cas_internal_a_SOURCES = \
  binary-to-hex.c \
  ca-cas-internal.h \
  detect-rotational.c \
  error.c \
  scan-objects.c \
  sha1-to-path.c \
  sha1.c \
  sha1.h \
  sha256.c \
  sha256.h
libca_cas_a_SOURCES = libca-cas.c error.c

libca_aws_a_SOURCES = aws.c sha256.c binary-to-hex.c

ca_cas_SOURCES = ca-cas.c
ca_cas_LDADD = libca-cas-internal.a

ca_cas_amazon_glacier_SOURCES = ca-cas-amazon-glacier.c
ca_cas_amazon_glacier_LDADD = $(PACKAGES_LIBS) libca-cas-internal.a libca-aws.a

ca_cas_repack_SOURCES = ca-cas-repack.c
ca_cas_repack_LDADD = libca-cas-internal.a

TESTS = aws_test sha256_test
check_PROGRAMS = $(TESTS)

aws_test_LDADD = $(PACKAGES_LIBS) libca-cas-internal.a libca-aws.a
sha256_test_LDADD = libca-cas-internal.a
