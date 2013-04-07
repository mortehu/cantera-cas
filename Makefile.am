lib_LIBRARIES = libca-cas.a
include_HEADERS = ca-cas.h
bin_PROGRAMS = \
  ca-cas \
  ca-cas-repack

ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = -I.
AM_CFLAGS = -Wall -Werror -g

ca_cas_SOURCES = ca-cas.c sha1.c sha1.h common.c
ca_cas_repack_SOURCES = ca-cas-repack.c common.c
libca_cas_a_SOURCES = libca-cas.c error.c
