lib_LTLIBRARIES = \
  libca-cas.la

bin_PROGRAMS = \
  ca-cas \
  ca-cas-balancerd \
  ca-cas-fsck \
  ca-casd

noinst_LIBRARIES =

noinst_LTLIBRARIES = \
  src/libbalancer.la \
  src/libcolumnfile.la \
  src/libutil.la \
  src/libsharding.la \
  src/libstorage.la \
  src/libproto.la

check_PROGRAMS = \
  src/balancer_test \
  src/storage-server_test

dist_check_SCRIPTS = \
  src/end2end_test.sh

ca_cas_includedir = $(includedir)/ca-cas
ca_cas_include_HEADERS = \
  src/cas-columnfile.h \
  src/client.h \
  src/key.h

ca_cas_proto_includedir = $(includedir)/ca-cas/proto
ca_cas_proto_include_HEADERS = \
  generated/src/proto/ca-cas.capnp.h \
  generated/src/proto/columnfile.capnp.h \
  generated/src/proto/util.capnp.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = ca-cas.pc

TESTS = $(check_PROGRAMS) $(dist_check_SCRIPTS)

ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = -Isrc -Igenerated/src
AM_LDFLAGS = -lpthread

include third_party/gtest/Makefile.am

EXTRA_DIST = \
  LICENSE \
  README.md \
  debian/ca-cas.dirs \
  debian/ca-cas.install \
  debian/changelog \
  debian/compat \
  debian/control \
  debian/copyright \
  debian/libca-cas-dev.dirs \
  debian/libca-cas-dev.install \
  debian/libca-cas0.dirs \
  debian/libca-cas0.install \
  debian/rules \
  debian/source/format

libca_cas_la_SOURCES = \
  src/client.cc \
  src/client.h
libca_cas_la_LIBADD = \
  src/libutil.la \
  src/libproto.la \
  $(CAPNP_RPC_LIBS) \
  $(CRYPTO_LIBS)
libca_cas_la_LDFLAGS = -no-undefined -version-info 0:0:0

src_libbalancer_la_SOURCES = \
  src/balancer.cc \
  src/balancer.h
src_libbalancer_la_LIBADD = \
  src/libsharding.la \
  libca-cas.la

src_libstorage_la_SOURCES = \
  src/async-io.cc \
  src/async-io.h \
  src/storage-server.cc \
  src/storage-server.h
src_libstorage_la_LIBADD = \
  $(CAPNP_RPC_LIBS) \
  $(CRYPTO_LIBS) \
  -lrt

src_libsharding_la_SOURCES = \
  src/sharding.cc \
  src/sharding.h
src_libsharding_la_LIBADD = \
  $(YAML_LIBS)

src_libutil_la_SOURCES = \
  src/bytestream.h \
  src/io.cc \
  src/io.h \
  src/key.cc \
  src/key.h \
  src/progress.cc \
  src/progress.h \
  src/rpc.h \
  src/sha1.h \
  src/util.cc \
  src/util.h
src_libutil_la_LIBADD = \
  $(CRYPTO_LIBS)

src_libcolumnfile_la_SOURCES = \
  src/cas-columnfile.cc

src_libproto_la_SOURCES = \
  generated/src/proto/async-io.capnp.c++ \
  generated/src/proto/async-io.capnp.h \
  generated/src/proto/columnfile.capnp.c++ \
  generated/src/proto/columnfile.capnp.h \
  generated/src/proto/ca-cas.capnp.c++ \
  generated/src/proto/ca-cas.capnp.h \
  generated/src/proto/util.capnp.c++ \
  generated/src/proto/util.capnp.h

ca_cas_fsck_SOURCES = \
  src/ca-cas-fsck.cc
ca_cas_fsck_LDADD = \
  src/libutil.la \
  $(CAPNP_LIBS) \
  $(CRYPTO_LIBS)

ca_cas_SOURCES = \
  src/ca-cas.cc
ca_cas_LDADD = \
  libca-cas.la \
  src/libutil.la \
  src/libsharding.la \
  src/libproto.la \
  $(CAPNP_RPC_LIBS) \
  $(CRYPTO_LIBS) \
  $(LIBCOLUMNFILE_LIBS) \
  $(YAML_LIBS)

ca_cas_balancerd_SOURCES = \
  src/ca-cas-balancerd.cc
ca_cas_balancerd_LDADD = \
  src/libbalancer.la \
  src/libutil.la \
  src/libproto.la \
  $(CAPNP_RPC_LIBS) \
  $(YAML_LIBS)

ca_casd_SOURCES = \
  src/ca-casd.cc
ca_casd_LDADD = \
  src/libstorage.la \
  src/libutil.la \
  src/libproto.la \
  $(CAPNP_RPC_LIBS) \
  $(YAML_LIBS)

src_balancer_test_SOURCES = \
  src/balancer_test.cc
src_balancer_test_LDADD = \
  src/libbalancer.la \
  src/libstorage.la \
  src/libutil.la \
  src/libproto.la \
  third_party/gtest/libgtest.a \
  $(CAPNP_RPC_LIBS) \
  $(YAML_LIBS)

src_storage_server_test_SOURCES = \
  src/storage-server_test.cc
src_storage_server_test_LDADD = \
  libca-cas.la \
  src/libstorage.la \
  src/libutil.la \
  src/libproto.la \
  third_party/gtest/libgtest.a \
  $(CAPNP_RPC_LIBS) \
  $(YAML_LIBS)

BUILT_SOURCES = \
  generated/src/proto/async-io.capnp.c++ \
  generated/src/proto/ca-cas.capnp.c++ \
  generated/src/proto/columnfile.capnp.c++ \
  generated/src/proto/util.capnp.c++

generated/src/proto/%.capnp.c++: src/proto/%.capnp
	$(AM_V_GEN)capnp compile -oc++:generated $<
