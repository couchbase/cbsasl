ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libcbsasl.la
pkginclude_HEADERS = include/cbsasl/cbsasl.h

libcbsasl_la_includedir = $(libdir)
libcbsasl_la_SOURCES = include/cbsasl/cbsasl.h \
                        src/config_static.h \
                        src/cbsasl.c \
                        src/hash.c \
                        src/hash.h \
                        src/pwfile.c \
                        src/pwfile.h

libcbsasl_la_CPPFLAGS = $(CPPFLAGS) -g -I$(top_srcdir)/include
libcbsasl_la_LDFLAGS = -R '$(pkglibdir)' -R '$(libdir)'
libcbsasl_la_CFLAGS = -std=c99

check_PROGRAMS= binary-sasl

basic_sasl_test_CPPFLAGS = $(CPPFLAGS) -I$(top_srcdir)/include
