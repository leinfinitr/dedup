AC_PREREQ([2.63])
AC_INIT([dedup], [0.9.1], [vass@fsl.cs.sunysb.edu])
AC_LANG(C)

AM_INIT_AUTOMAKE
AM_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries and adds the found ones to LIBS variable
AC_CHECK_LIB(crypto, MD5)
AC_CHECK_LIB(z, deflate)

# Checks for header files.
AC_CHECK_HEADERS([openssl/sha.h])
AC_CHECK_HEADERS([openssl/md5.h])

AC_CHECK_HEADERS([zlib.h])

AC_OUTPUT(Makefile)
