AC_INIT([ca-cas], [1.1.1])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])

AC_CONFIG_MACRO_DIR([m4])

AM_MAINTAINER_MODE([disable])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

PKG_CHECK_MODULES([CAPNP], [capnp >= 0.6])
PKG_CHECK_MODULES([CAPNP_RPC], [capnp-rpc >= 0.6])
PKG_CHECK_MODULES([CRYPTO], [libcrypto])
PKG_CHECK_MODULES([LIBCOLUMNFILE], [libcolumnfile])
PKG_CHECK_MODULES([YAML], [yaml-cpp >= 0.5])

AC_CHECK_PROGS([SWIG], [swig], ["noswig"])
AC_ARG_ENABLE([python], [AS_HELP_STRING([--disable-python], [build without the python bindings])], [enable_python=$enableval], [enable_python=check])

AM_PROG_AR
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_MAKE_SET

LT_INIT

AC_LANG_PUSH([C++])
AX_CXX_COMPILE_STDCXX_14([], [])
AC_LANG_POP([C++])

if test "x$SWIG" = xnoswig && test "x$enable_python" = xyes; then
  #don't even bother when swig is not found
  AC_MSG_ERROR([--enable-python was given as an option but swig was not found on the system])
elif test "x$SWIG" = xswig && test "x$enable_python" != xno; then
  #verify the python installation
  AM_PATH_PYTHON([3], [PYTHON_FOUND=true], [PYTHON_FOUND=false])
  if test "x$PYTHON_FOUND" = xtrue; then
    PYTHON_CPPFLAGS=
    PYTHON_LDFLAGS=
    AX_PYTHON_DEVEL
    if test "x$PYTHON" = x; then
      if test "x$enable_python" = xyes; then
	AC_MSG_ERROR([Incomplete python development package])
      else
	AC_MSG_WARN([Incomplete python development package])
      fi
      VALID_PYTHON=no
    else
      VALID_PYTHON=yes
    fi
  fi
fi

if test "x$VALID_PYTHON" = xyes; then
  AC_MSG_NOTICE([Building with Python bindings])

  pythondir=$PYTHON_SITE_PKG
  pyexecdir=$PYTHON_SITE_PKG_EXEC

  AC_SUBST(PYTHONDIR,$pythondir)
  AC_SUBST(PKGPYTHONDIR,$pkgpythondir)
  AC_SUBST(PYEXECDIR,$pyexecdir)
  AC_SUBST(PKGPYEXECDIR,$pkgpyexecdir)
fi

AM_CONDITIONAL([ENABLE_PYTHON],[test x$VALID_PYTHON = xyes])

AC_CONFIG_FILES([Makefile ca-cas.pc])
AC_OUTPUT
