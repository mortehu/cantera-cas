noinst_LIBRARIES = libca-cas-internal.a
lib_LIBRARIES = libca-cas.a
include_HEADERS = ca-cas.h
bin_PROGRAMS = \
  ca-cas \
  ca-cas-repack

ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = -I.
AM_CFLAGS = -Wall -Werror -g -fPIC

libca_cas_internal_a_SOURCES = \
  binary-to-hex.c \
  ca-cas-internal.h \
  detect-rotational.c \
  error.c \
  scan-objects.c \
  sha1-to-path.c \
  sha1.c \
  sha1.h
libca_cas_a_SOURCES = libca-cas.c error.c

ca_cas_SOURCES = ca-cas.c
ca_cas_LDADD = libca-cas-internal.a

ca_cas_repack_SOURCES = ca-cas-repack.c
ca_cas_repack_LDADD = libca-cas-internal.a
