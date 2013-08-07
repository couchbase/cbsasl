ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libcbsasl.la
pkginclude_HEADERS = include/cbsasl/cbsasl.h

libcbsasl_la_includedir = $(libdir)
libcbsasl_la_SOURCES = include/cbsasl/cbsasl.h \
                        src/config_static.h \
                        src/cbsasl.c \
                        src/cram-md5/cram-md5.c \
                        src/cram-md5/cram-md5.h \
                        src/cram-md5/hmac.c \
                        src/cram-md5/hmac.h \
                        src/hash.c \
                        src/hash.h \
                        src/cram-md5/md5.c \
                        src/cram-md5/md5.h \
                        src/plain/plain.c \
                        src/plain/plain.h \
                        src/pwfile.c \
                        src/pwfile.h

libcbsasl_la_CPPFLAGS = $(CPPFLAGS) -g -I$(top_srcdir)/include
libcbsasl_la_LDFLAGS = -R '$(pkglibdir)' -R '$(libdir)'
libcbsasl_la_CFLAGS = -std=c99

check_PROGRAMS = hmac_test \
                 pwfile_test \
                 sasl_test

TESTS=${check_PROGRAMS}

hmac_test_CPPFLAGS = $(CPPFLAGS)
hmac_test_SOURCES = t/hmac_test.c src/cram-md5/hmac.c src/cram-md5/md5.c
hmac_test_DEPENDENCIES = src/cram-md5/hmac.h src/cram-md5/md5.h

pwfile_test_CPPFLAGS = $(CPPFLAGS) -I$(top_srcdir)/include
pwfile_test_SOURCES = t/pwfile.c src/pwfile.c src/hash.c
pwfile_test_DEPENDENCIES = src/pwfile.h src/hash.h

sasl_test_CPPFLAGS = $(CPPFLAGS) -I$(top_srcdir)/include
sasl_test_SOURCES = t/sasl_server_test.c
sasl_test_DEPENDENCIES = include/cbsasl/cbsasl.h
sasl_test_LDADD = libcbsasl.la
