#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])
m4_include([m4/version.m4])
AC_INIT([cbsasl], [VERSION_NUMBER], abhinav@couchbase.com)
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_SRCDIR([src/cbsasl.c])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_LIBTOOL
AC_C_BIGENDIAN

# Set up src/config.h file

AH_TOP([
/*
 *     Copyright 2013 Couchbase, Inc.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#ifndef SRC_CONFIG_H_
#define SRC_CONFIG_H_ 1
])

AH_BOTTOM([
#include "config_static.h"
#endif  // SRC_CONFIG_H_
])

# Checks for programs.
AC_PROG_CXX

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([assert.h ctype.h errno.h pthread.h stdarg.h stdbool.h \
                  stdint.h stdio.h stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT32_T
AC_TYPE_SIZE_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([strdup strerror])
AC_CONFIG_FILES(Makefile)
AC_OUTPUT
