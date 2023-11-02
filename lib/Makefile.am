
LIB_CFILES = cert.c \
conn.c

LIB_HFILES = cert.h \
conn.h \
snif.h

pkginclude_HEADERS = $(LIB_HFILES)

lib_LTLIBRARIES = libsnif.la

libsnif_la_SOURCES = $(LIB_CFILES) $(LIB_HFILES)
libsnif_la_LIBADD = -lssl -lcrypto -lcurl
libsnif_la_LDFLAGS = -version-info 0:0:0
