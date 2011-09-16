# Makefile for sharktools

prefix = @prefix@
datarootdir = @datarootdir@
datadir = @datadir@

CC=@CC@
OLDCFLAGS=@CFLAGS@

all: @PYSHARK@ @MATSHARK@ sharktools_test
	@echo -n

#CC=gcc
CFLAGS=-g -Wall -DHAVE_CONFIG_H -fPIC -O2 @DEFS@

GLIB_2_0_CFLAGS=@GLIB_2_0_CFLAGS@
GLIB_2_0_LIBS=@GLIB_2_0_LIBS@

WIRESHARK_CFLAGS=@WIRESHARK_CFLAGS@
WIRESHARK_LIBS=@WIRESHARK_LIBS@

INCLUDEFLAGS=-I. $(WIRESHARK_CFLAGS) $(GLIB_2_0_CFLAGS)

LIBSHARKTOOLS_SRCS=sharktools_cfile.c \
sharktools_core.c \
sharktools_add_decode_as.c \
sharktools_frame_data.c \
sharktools_epan.c

LIBSHARKTOOLS_OBJECTS=$(LIBSHARKTOOLS_SRCS:.c=.o)

LIBPATH=-L.
#LIBS=-lsharktools $(WIRESHARK_LIBS) $(GLIB_2_0_LIBS)
LIBS=$(GLIB_2_0_LIBS) $(WIRESHARK_LIBS) -lsharktools

MEX=@MEX@
MEXEXT=@MEXEXT@
MEXARCH=@MEXARCH@  # Needed for MacOSX target OS

PY_CC=@PY_CC@
PY_OPT=@PY_OPT@
PY_BASECFLAGS=@PY_BASECFLAGS@
PY_CCSHARED=@PY_CCSHARED@
PY_LDSHARED=@PY_LDSHARED@
PY_SHLIBSUFFIX=@PY_SHLIBSUFFIX@
PY_INCLUDE_FLAGS=@PY_INCLUDE_FLAGS@

PY_CPPFLAGS=$(PY_BASECFLAGS) $(PY_OPT)

# EXTRA_DIST is an automake thing:
#EXTRA_DIST = $(LIBSHARKTOOLS_SRCS)

sharktools_%.o: sharktools_%.c
	$(CC) -o $@ -c $(CFLAGS) $(INCLUDEFLAGS) $< 

sharktools: $(LIBSHARKTOOLS_OBJECTS)
	@echo "--- making sharktools ---"
	ar rc libsharktools.a $(LIBSHARKTOOLS_OBJECTS)
	ranlib libsharktools.a

sharktools_test: sharktools_test.o
	@echo "--- making sharktools_test ---"
	$(CC) -o $@ $< $(LIBPATH) $(LIBS)

matshark: sharktools
	@echo "--- making matshark ---"
	$(MEX) $(MEXARCH) -cxx -o $@ matshark.c $(LIBPATH) $(LIBS) $(INCLUDEFLAGS)

pyshark.os:
	$(PY_CC) -o $@ -c $(CFLAGS) -fPIC $(PY_CPPFLAGS) -DSWIG_GLOBAL $(PY_INCLUDE_FLAGS) $(INCLUDEFLAGS) pyshark.c

pyshark: pyshark.os sharktools
	@echo "--- making pyshark ---"
	$(PY_LDSHARED) -o $@$(PY_SHLIBSUFFIX) $(CFLAGS) $< $(LIBPATH) $(LIBS)

clean:
	rm -f sharktools_*.o
	rm -f libsharktools.a
	rm -f matshark.mex*
	rm -f pyshark.os
	rm -f pyshark$(PY_SHLIBSUFFIX)


