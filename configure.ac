# configure.ac file for sharktools
#
# Questions: Armen Babikyan <armenb@static.net>
#
# NB: After editing this file, run "autoconf" to generate a
# new ./configure script

AC_PREREQ(2.59)

AC_INIT(sharktools, 0.1.8, armenb@static.net)
AM_INIT_AUTOMAKE(sharktools, 0.1.8)

#AC_CONFIG_HEADER([src/sharktools_config.h])

dnl Checks for programs.
AC_PROG_CC

if [ test "x$CC" == "x" ];
then
   AC_MSG_ERROR(C compiler (preferably gcc) is necessary for compilation of sharktools)
fi

AC_LANG_C

# mex looks for g++
AC_PROG_CXX
if [ test "x$CXX" == "x" ];
then
   AC_MSG_WARN(C++ compiler (preferably g++) is necessary for compilation of matshark - mex wants it)
fi

# figured these out from autoscan:
AC_CHECK_FUNCS([strchr]) # wanted by: matshark.c:382
AC_CHECK_FUNCS([strdup]) # wanted by: pyshark.c:293
AC_CHECK_FUNCS([strerror]) # wanted by: sharktools_core.c:353
AC_C_CONST # wanted by: matshark.c:62
AC_C_INLINE # wanted by: pyshark.c:95
AC_FUNC_VPRINTF # wanted by: sharktools_core.c:342
AC_PROG_RANLIB # wanted by: Makefile.in:56

AC_ARG_ENABLE(debug,
              [--enable-debug   Turn on debugging output in sharktools.  ],
              [case "${enableval}" in
               yes) debug=true ;;
               no)  debug=false ;;
               *) AC_MSG_ERROR(bad value ${enableval} for --enable-debug) ;;
               esac],[debug=false])

#AC_DEFINE([WIRESHARK_1_0_0], [], [Use Wireshark 1.0.* support])
#AC_DEFINE([WIRESHARK_1_2_0], [], [Use Wireshark 1.2.* support])
#AC_DEFINE([WIRESHARK_1_4_0], [], [Use Wireshark 1.4.* support])

AC_DEFINE(DEBUG,[0], [Turn debugging on or off])
if test ${debug} = "true";
then
   AC_DEFINE(DEBUG,[1])
fi

#AM_CONDITIONAL(DEBUG, test x$debug = xtrue)

#CPPFLAGS="-I$PY_INCLUDE_DIRS"
#echo CPPFLAGS=$CPPFLAGS
#AC_CHECK_HEADERS(glib.h,
#        [],
#        AC_MSG_ERROR([glib.h not found.  Install libglib-2.0-dev{el} package]))

#AM_CONDITIONAL([DARWIN], [test x$(uname) == xDarwin])

PKG_CHECK_MODULES(GLIB_2_0, glib-2.0 gmodule-2.0, glib_found=yes, glib_found=no)

WIRESHARK_LIBS="-lwireshark -lwiretap"

# MacOSX is a pain to configure for.

# glib installation options:
# * Using fink vs MacPorts
# * compiled as 32-bit vs 64-bit
# -> 2 degrees of freedom, 4 options.

# wireshark installation options:
# * Using fink, MacPorts or wireshark.org's .dmg installer
# * compiled as 32-bit vs. 64-bit
# -> 2 degrees of freedom, 6 options

# Python installation options:
# * Using Apple's Python vs fink's python
# * compiled as 32-bit vs. 64-bit
# -> 2 degrees of freedom, 4 options

# Matlab installation options:
# * Run as a 32-bit vs. 64-bit program

AC_MSG_CHECKING(for MacOSX)
if [ test "x$(uname)" == "xDarwin" ] ; then
   AC_MSG_RESULT(yes) # "for MacOSX"

   ###### Collect a bunch of information ######
   
   # Set the homebrew path
   AC_ARG_WITH([brew],
               AC_HELP_STRING([--with-brew=@<:@DIR@:>@],
                              [MacOSX only, default /usr/local]),
               [brew_path="$withval"],
               [brew_path="/usr/local"])

   # Set the fink path
   AC_ARG_WITH([fink],
               AC_HELP_STRING([--with-fink=@<:@DIR@:>@],
                              [MacOSX only, default /sw]),
               [fink_path="$withval"],
               [fink_path="/sw"])

   # Set the Macports path
   AC_ARG_WITH([macports],
               AC_HELP_STRING([--with-macports=@<:@DIR@:>@],
                              [MacOSX only, default /opt/local]),
               [macports_path="$withval"],
               [macports_path="/opt/local"])

   # Set the Wireshark.app path
   AC_ARG_WITH([wireshark-app],
               AC_HELP_STRING([--with-wireshark-app=@<:@DIR@:>@],
                              [MacOSX only, default /Applications/Wireshark.app]),
               [wiresharkapp_path="$withval"],
               [wiresharkapp_path="/Applications/Wireshark.app"])

   #AC_CHECK_FILE($fink_path/bin/fink,
   #              [FINK=$fink_path/bin/fink],
   #              [no])

   # See if brew actually exists
   AC_MSG_CHECKING(for brew)
   if [ test -e $brew_path/bin/brew ] ; then
      AC_MSG_RESULT(yes: $brew_path/bin/brew)

      # See if Wireshark exists in brew
      AC_MSG_CHECKING(for Wireshark in brew)
      if [ test -e $brew_path/bin/wireshark ] ; then
         AC_MSG_RESULT(yes: $brew_path/bin/wireshark)
         WIRESHARK_BREW="$brew_path/bin/wireshark"
      else
         AC_MSG_RESULT(no)
         WIRESHARK_BREW="no"
      fi
   else
      AC_MSG_RESULT(no)
   fi

   # See if fink actually exists
   AC_MSG_CHECKING(for fink)
   if [ test -e $fink_path/bin/fink ] ; then
      AC_MSG_RESULT(yes: $fink_path/bin/fink)

      # See if Wireshark exists in fink
      AC_MSG_CHECKING(for Wireshark in Fink)
      if [ test -e $fink_path/bin/wireshark ] ; then
         AC_MSG_RESULT(yes: $fink_path/bin/wireshark)
         WIRESHARK_FINK="$fink_path/bin/wireshark"
      else
         AC_MSG_RESULT(no)
         WIRESHARK_FINK="no"
      fi
   else
      AC_MSG_RESULT(no)
   fi

   # See if MacPorts actually exists
   AC_MSG_CHECKING(for MacPorts)
   if [ test -e $macports_path/bin/port ] ; then
      AC_MSG_RESULT(yes: $macports_path/bin/port)
      #MACPORTS="$macports_path/bin/port"

      # See if Wireshark exists in MacPorts
      AC_MSG_CHECKING(for Wireshark in MacPorts)
      if [ test -e $macports_path/bin/wireshark ] ; then
         AC_MSG_RESULT(yes: $macports_path/bin/wireshark)
         WIRESHARK_MACPORTS="$macports_path/bin/wireshark"
      else
         AC_MSG_RESULT(no)
         WIRESHARK_MACPORTS="no"
      fi
   else
      AC_MSG_RESULT(no: $macports_path/bin/port not found)
      #MACPORTS="no"
   fi

   # Is Wireshark.dmg installed?
   AC_MSG_CHECKING(to see if Wireshark.org's dmg is installed (we can't use it, but good to know))
   if [ test -e $wiresharkapp_path/Contents/Resources/bin/wireshark ] ; then
      AC_MSG_RESULT(yes: $wiresharkapp_path/Contents/Resources/bin/wireshark)
      WIRESHARK_APP="$wiresharkapp_path/Contents/Resources/bin/wireshark"
   else
      AC_MSG_RESULT(no)
      WIRESHARK_APP="no"
   fi

   LIBWIRESHARK_DEFAULT="/Applications/Wireshark.app/Contents/Resources/lib/libwireshark.dylib"
   # Set the Wireshark.app path
   AC_ARG_WITH([libwireshark],
               AC_HELP_STRING([--with-libwireshark=@<:@FILE@:>@],
                              [MacOSX only, default $LIBWIRESHARK_DEFAULT]),
               [libwireshark_path="$withval"],
               [libwireshark_path=$LIBWIRESHARK_DEFAULT])

   AC_CHECK_FILE($libwireshark_path,
                 [],
                 [
		  AC_MSG_ERROR(On MacOSX, use --with-libwireshark to locate your wireshark library.)
                 ])

   WIRESHARK_LIBPATH="-L$(dirname $libwireshark_path)"
   #WIRESHARK_RPATH="-Wl,-rpath $(dirname $libwireshark_path),$(basename $libwireshark_path)"
   WIRESHARK_RPATH="-Wl,-rpath $(dirname $libwireshark_path)"

   AC_MSG_CHECKING(the word size of libwireshark)
   if [ test $(file -L $libwireshark_path | grep -c 'x86_64') == 1] ;
   then
      AC_MSG_RESULT(found 64-bit libwireshark!)
      ARCH_FLAG="-m64"
   elif [ test $(file -L $libwireshark_path | grep -c 'i386') == 1] ;
   then
      AC_MSG_RESULT(found 32-bit libwireshark!)
      ARCH_FLAG="-m32"
   else
      AC_MSG_RESULT(Didn't understand the output of file.  Assuming 64bit...)
      ARCH_FLAG="-m64"
   fi


   ###### Use the given information to make a decision ######

   #   AC_CHECK_PROG(MACPORTS,fink, "/sw/bin/fink", no, [path= '/sw/bin'])

   #AC_PATH_PROG(PKGCONFIG,"pkg-config",
   #             [],
   #             [AC_MSG_ERROR(Could not find pkg-config.  If you are using fink or MacPorts, add their binary directories to your path.)])

   # Prioritize fink over macports:   
   #AC_CHECK_FILE($fink_path/lib/libwireshark.0.dylib,
   #             [
   #             # fink doesn't create /sw/lib/libwireshark.dylib because
   #             # it's not supposed to be "user-serviceable".  So we have
   #             # to modify our -l flags
   #             #WIRESHARK_LIBS="-lwireshark.0 -lwiretap.0"]
   #             ]
   #             )

   #CPPFLAGS="$CPPFLAGS -I/sw/in"
else
   AC_MSG_RESULT(no) # "for MacOSX"
fi

AC_MSG_CHECKING(for Linux)
if [ test "x$(uname)" == "xLinux" ] ; then
   AC_MSG_RESULT(yes) # "for Linux"
   AC_CHECK_PROG(LSB_RELEASE, lsb_release, [lsb_release], [])

   if [ test "x$LSB_RELEASE" == "xlsb_release" ];
   then
      AC_MSG_CHECKING(for Ubuntu)
      if [ test "x$(lsb_release --id | grep -c Ubuntu)" == "x1" ] ;
      then
         AC_MSG_RESULT(yes) # "for Ubuntu"
         # We are configuring for Ubuntu!  Inconveniently,
         # Ubuntu puts libwireshark.so and libwiretap.so in a directory
         # that's not in ld search path, either for linking or runtime.
         # So we must add -Wl,-rpath and -L flags here:
         WIRESHARK_LIBPATH="-L/usr/lib/wireshark"
         WIRESHARK_RPATH="-Wl,-rpath=/usr/lib/wireshark"
      else
         AC_MSG_RESULT(no) # "for Ubuntu"
      fi
   else
      AC_MSG_WARN(Could not find lsb_release, so could not determine Linux distribution!)
   fi

else
   AC_MSG_RESULT(no) # "for Linux"
fi

# Okay, I don't know what to make the GLIB requirement, but I know it works on Glib as old
# as Glib 2.12.3
AM_PATH_GLIB_2_0([2.0.0],,[AC_MSG_ERROR([*** GLIB >= 2.0.0 not installed - please install first ***])])

#CPPFLAGS="$CFLAGS $(pkg-config --cflags glib-2.0 gmodule-2.0)"
#LDFLAGS="$LDFLAGS $(pkg-config --libs glib-2.0 gmodule-2.0)"

#AC_CHECK_LIB(glib2.0, g_new)
#AC_CHECK_LIB(gmodule2.0, g_module_open)

AC_PATH_PROG(WIRESHARK, wireshark)

# -L dereferences $WIRESHARK in case it is a symlink
#TMP=$(file -L $WIRESHARK)
# m4 doesn't let you escape square brackets so we
# use @<:@ and @:>@ instead. (technique called "quadrigraph")
#FILTER='s/.*@<:@^0-9@:>@\(@<:@0-9@:>@*\)-bit.*/\1/g'
#echo FILTER=$FILTER
#WIRESHARK_WORD_SIZE=$(echo $TMP | sed -e $FILTER)
#echo WSS=$WIRESHARK_WORD_SIZE

AC_ARG_WITH([wireshark-src],
            AC_HELP_STRING([--with-wireshark-src=@<:@DIR@:>@],
                           [wireshark string]),
            with_wireshark_src="$withval",
            with_wireshark_src="UNDEF")

if [ test "x$with_wireshark_src" = "xUNDEF" ] ;
then
   AC_MSG_ERROR(Required parameter: you need to set --with-wireshark-src=/path/to/wiresharksource-x.y.z)
fi

# Check to make sure wireshark directory specified actually exists:
AC_CHECK_FILE($with_wireshark_src,
              [],
              [AC_MSG_ERROR(Non-existent directory specified: $with_wireshark_src)])

WIRESHARK_CONFIG_H_FILE=$with_wireshark_src/config.h
#echo WCHF=$WIRESHARK_CONFIG_H_FILE

# Check to make sure ./configure has been run in the wireshark source directory
AC_CHECK_FILE($WIRESHARK_CONFIG_H_FILE,
              [],
              [AC_MSG_ERROR(need to run ./configure --disable-wireshark in the wireshark directory)])

WIRESHARK_CFLAGS="-I$with_wireshark_src -I$with_wireshark_src/wiretap"

TMP=$(grep "#define VERSION " $WIRESHARK_CONFIG_H_FILE)
#echo $TMP
#echo "'s/.*\ \\\"\(@<:@0-9@:>@@<:@0-9@:>@*\).\(@<:@0-9@:>@@<:@0-9@:>@*\)\.\(@<:@0-9@:>@@<:@0-9@:>@*\)\\\"/\1/g'"
WIRESHARK_VERSION_MAJOR=$(echo $TMP | sed -e 's/[[^0-9.]]*\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)\"/\1/g')
WIRESHARK_VERSION_MINOR=$(echo $TMP | sed -e 's/[[^0-9.]]*\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)\"/\2/g')
WIRESHARK_VERSION_SUBMINOR=$(echo $TMP | sed -e 's/[[^0-9.]]*\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)\"/\3/g')

echo "Wireshark version detected: $WIRESHARK_VERSION_MAJOR.$WIRESHARK_VERSION_MINOR.$WIRESHARK_VERSION_SUBMINOR"

if test $WIRESHARK_VERSION_MAJOR == 0; then
   echo "old"
elif test $WIRESHARK_VERSION_MAJOR == 1; then
   if test $WIRESHARK_VERSION_MINOR == 0; then
      echo "Configuring for Wireshark 1.0.*"
      AC_DEFINE(WIRESHARK_1_0_0)
   elif test $WIRESHARK_VERSION_MINOR == 2; then
      echo "Configuring for Wireshark 1.2.*"
      AC_DEFINE(WIRESHARK_1_2_0)
      WIRESHARK_LIBS="$WIRESHARK_LIBS -lwsutil"
   elif test $WIRESHARK_VERSION_MINOR == 4; then
      echo "Configuring for Wireshark 1.4.*"
      AC_DEFINE(WIRESHARK_1_4_0)
      WIRESHARK_LIBS="$WIRESHARK_LIBS -lwsutil"
   elif test $WIRESHARK_VERSION_MINOR == 6; then
      echo "Configuring for Wireshark 1.6.*"
      AC_DEFINE(WIRESHARK_1_6_0)
      WIRESHARK_LIBS="$WIRESHARK_LIBS -lwsutil"
   elif test $WIRESHARK_VERSION_MINOR == 8; then
      echo "Configuring for Wireshark 1.8.*"
      AC_DEFINE(WIRESHARK_1_8_0)
      WIRESHARK_LIBS="$WIRESHARK_LIBS -lwsutil"
   elif test $WIRESHARK_VERSION_MINOR == 10; then
      echo "Configuring for Wireshark 1.10.*"
      AC_DEFINE(WIRESHARK_1_10_0)
      WIRESHARK_LIBS="$WIRESHARK_LIBS -lwsutil"
   else
      echo "Configuring for Wireshark 1.10.*"
      AC_MSG_WARN((wireshark version is really new! Trying 1.10.0 support...))
      AC_DEFINE(WIRESHARK_1_10_0)
   fi
else
   AC_MSG_WARN((wireshark version is really, really new! Trying 1.10.0 support...))
   AC_DEFINE(WIRESHARK_1_10_0)
fi


# Allow user to choose whether to generate pyshark
# Default is enabled
AC_ARG_ENABLE([pyshark],
              [AS_HELP_STRING([--enable-pyshark],
              [create pyshark (default is no)])],
              [if test "$enableval" == yes; then
                  enable_pyshark=yes
               elif test "$enableval" == no; then
                  enable_pyshark=no
               else
                  AC_MSG_ERROR([bad value ${enableval} for --enable-pyshark])
               fi
               ],
              [enable_pyshark=no]
              )

if [ test "$enable_pyshark" = "yes" ] ;
then
   # This populates a dependency for the "all" target in the Makefile
   PYSHARK="pyshark"
   AC_SUBST(PYSHARK)

   # User can optionally specify where the python program is located
   # useful for situations like MacOSX, where there's a system
   # Python install (/usr/bin/python) and an optional fink python
   # (/sw/bin/python)
   AC_ARG_WITH([python],
               AC_HELP_STRING([--with-python=@<:@/path/to/python@:>@],
                              [Default is the first that shows up in in your path]),
               [# Check to see that the user's input was valid:
               AC_CHECK_FILE($withval, 
                             [PYTHON="$withval"],
                             [AC_MSG_ERROR(Could not find python located at $withval)])
               ],
               [# User didn't specify python, so look for it in the user's path:
               AC_PATH_PROG(PYTHON, python)
               ])

   if [ test "x$PYTHON" = x ] ;
   then
      AC_MSG_ERROR(I couldn't find python. Use --with-python or add it to your PATH variable)
   fi
   AC_SUBST(PYTHON)

   # Invoke $PYTHON, the python interpreter, and make its distutils module
   # tell us what build options to use:        
   PY_CC=$($PYTHON -c "import distutils.sysconfig;print distutils.sysconfig.get_config_vars('CC')@<:@0@:>@")
   echo PY_CC=$PY_CC
   AC_SUBST(PY_CC)
   PY_OPT=$($PYTHON -c "import distutils.sysconfig;print distutils.sysconfig.get_config_vars('OPT')@<:@0@:>@")
   echo PY_OPT=$PY_OPT
   AC_SUBST(PY_OPT)
   PY_BASECFLAGS=$($PYTHON -c "import distutils.sysconfig;print distutils.sysconfig.get_config_vars('BASECFLAGS')@<:@0@:>@")
   echo PY_BASECFLAGS=$PY_BASECFLAGS
   AC_SUBST(PY_BASECFLAGS)
   PY_CCSHARED=$($PYTHON -c "import distutils.sysconfig;print distutils.sysconfig.get_config_vars('CCSHARED')@<:@0@:>@")
   echo PY_CCSHARED=$PY_CCSHARED
   AC_SUBST(PY_CCSHARED)
   PY_LDSHARED=$($PYTHON -c "import distutils.sysconfig;print distutils.sysconfig.get_config_vars('LDSHARED')@<:@0@:>@")
   echo PY_LDSHARED=$PY_LDSHARED
   AC_SUBST(PY_LDSHARED)
   PY_SHLIBSUFFIX=$($PYTHON -c "import distutils.sysconfig;print distutils.sysconfig.get_config_vars('SO')@<:@0@:>@")
   echo PY_SHLIBSUFFIX=$PY_SHLIBSUFFIX
   AC_SUBST(PY_SHLIBSUFFIX)
   PY_INCLUDE_DIRS=$($PYTHON -c "import distutils.sysconfig;print distutils.sysconfig.get_python_inc()")
   # Append -I to the directory:
   PY_INCLUDE_FLAGS=-I$PY_INCLUDE_DIRS
   echo PY_INCLUDE_FLAGS=$PY_INCLUDE_FLAGS
   AC_SUBST(PY_INCLUDE_FLAGS)

   CPPFLAGS="$PY_INCLUDE_FLAGS"
   echo CPPFLAGS=$CPPFLAGS
   AC_CHECK_HEADERS(Python.h,
                    [],
                    AC_MSG_ERROR([Python.h not found! Cannot build pyshark.  Please install python development libraries on your system (e.g. apt-get install python-dev or yum install python-devel)])
                    )
fi

# Allow user to choose whether to generate matshark
# Default is enabled
AC_ARG_ENABLE([matshark],
              [AS_HELP_STRING([--enable-matshark],
              [create matshark (default is no)])],
              [if test "$enableval" == yes; then
                  enable_matshark=yes
               elif test "$enableval" == no; then
                  enable_matshark=no
               else
                  AC_MSG_ERROR([bad value ${enableval} for --enable-matshark])
               fi
               ],
              [enable_matshark=no]
              )

if [ test "$enable_matshark" = "yes" ] ;
then
   # This populates a dependency for the "all" target in the Makefile
   MATSHARK="matshark"
   AC_SUBST(MATSHARK)

   # PKG_CHECK_MODULES(GLIB_2_0, ...) seems to include -pthread in
   # both the GLIB_2_0_CFLAGS and GLIB_2_0_LIBS vars on Ubuntu.
   # This confuses mex, so lets remove it if it exists:
   GLIB_2_0_LIBS=$(echo $GLIB_2_0_LIBS | sed -e 's/-pthread//g')
   AC_SUBST(GLIB_2_0_LIBS)
   GLIB_2_0_CFLAGS=$(echo $GLIB_2_0_CFLAGS | sed -e 's/-pthread//g')
   AC_SUBST(GLIB_2_0_CFLAGS)

   # User can optionally specify where the mex program is located
   AC_ARG_WITH([mex],
               AC_HELP_STRING([--with-mex=@<:@/path/to/mex@:>@],
                              [Default is the first that shows up in in your path]),
               [# Check to see that the user's input was valid:
               AC_CHECK_FILE($withval, 
                             [MEX="$withval"],
                             [AC_MSG_ERROR(Could not find mex located at $withval)])
               ],
               [# User didn't specify mex, so look for it in the user's path:
               AC_PATH_PROG(MEX, "mex")
               ]
               )

   if test "x$MEX" = x
   then
      if test "x$(uname)" = "Darwin"
      then
         AC_MSG_WARN(MacOSX: couldn't find mex. Use --with-mex=/Applications/MATLAB_<version>.app/Contents/Resources/bin/mex or add the directory to your PATH variable)
      fi

      AC_MSG_ERROR(I couldn't find mex.  Use --with-mex or add it to your PATH variable)
   fi
   AC_SUBST(MEX)

   OS=$(uname)
   # echo OS=$OS
   if [ test "x$OS" = "xLinux" ] ;
   then
      ARCH=$(uname -m)
      if [ test "x$ARCH" = "x86_64" ] ;
      then
         MEXEXT=mexa64
      elif [ test "x$ARCH" = "i386" ] ;
      then
         MEXEXT=mexglx
      fi
   elif [ test "x$OS" = "xDarwin" ] ;
   then
      ARCH=$(uname -p)
      if test "x$ARCH" = "i386"
      then
         MEXEXT=mexmaci
         MEXARCH=-maci
      else
         MEXEXT=mexmaci64
         MEXARCH=-maci64
      fi
      AC_SUBST(MEXARCH)
   fi
   AC_SUBST(MEXEXT)
   echo MEXARCH=$MEXARCH
   echo MEXEXT=$MEXEXT
fi

AC_SUBST(WIRESHARK_CFLAGS)

# Override whatever libpath we've automatically chosen in this file:
AC_ARG_WITH([wireshark-libpath],
            AC_HELP_STRING([--with-wireshark-libpath=@<:@DIR@:>@],
                           [Since libwireshark is not supposed to be "user serviceable",
                            it is sometimes not in the LD search path.  This option lets
                            you manually specify what wireshark libraries to link and rpath to.]),
            [WIRESHARK_LIBPATH="-L$withval"
             WIRESHARK_RPATH="-Wl,-rpath=$withval"
             ],
            [])

# Prepend the (possibly) user-specified Library path to WIRESHARK_LIBS
WIRESHARK_LIBS="$WIRESHARK_RPATH $WIRESHARK_LIBPATH $WIRESHARK_LIBS"
AC_SUBST(WIRESHARK_LIBS)

# This package cheats a little and utilizes a config.h from
# another project: wireshark.  We need to undefine these -D arguments
AC_UNDEFINE(PACKAGE)
AC_UNDEFINE(VERSION)
AC_UNDEFINE(PACKAGE_NAME)
AC_UNDEFINE(PACKAGE_STRING)
AC_UNDEFINE(PACKAGE_TARNAME)
AC_UNDEFINE(PACKAGE_VERSION)
AC_UNDEFINE(PACKAGE_BUGREPORT)

AC_DEFUN([AC_DATAROOTDIR_CHECKED])

AC_CONFIG_FILES([
src/Makefile
Makefile
])
AC_OUTPUT




