#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.


AC_PREREQ([2.69])
AC_INIT([snif], [0.90], [bugs@vesvault.com])
AC_CONFIG_SRCDIR([snifd/snifd.c])
AC_CONFIG_HEADERS([config.h])

AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([1.0 subdir-objects])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

# Checks for header files.
AC_CHECK_HEADERS([string.h stddef.h fcntl.h unistd.h sys/ioctl.h openssl/evp.h curl/curl.h poll.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_OFF_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([strdup strndup memmove memset strerror poll])

AC_PREFIX_DEFAULT(/usr)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
