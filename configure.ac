AC_PREREQ([2.71])
AC_INIT([ax25-apps],[0.0.8-rc5],[linux-hams@vger.kernel.org])
AC_CONFIG_SRCDIR(ax25ipd/config.c)
AM_INIT_AUTOMAKE([1.7])

AC_CONFIG_HEADERS(config.h)

dnl Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_GCC_TRADITIONAL

dnl Checks for libraries.
AC_SUBST(AX25_LIB)
AC_SUBST(NCURSES_LIB)
AC_CHECK_LIB(ax25, ax25_config_load_ports, AX25_LIB="-lax25", AC_MSG_ERROR(Could not find the libax25 libraries; aborting))
AC_CHECK_LIB(ncursesw, initscr,NCURSES_LIB="-lncursesw", AC_MSG_ERROR(Could not find the ncursesw library; aborting))

dnl Checks for working glibc 2.1 headers
AC_CHECK_TYPES([struct ax25_fwd_struct], [],
	[AC_MSG_ERROR([Both glibc and libax25 are too old or both installed])],
	[[#include <netax25/ax25.h>]])
AC_CHECK_MEMBER([struct nr_route_struct.ndigis], [],
	[AC_MSG_ERROR([Both glibc and libax25 are too old or both installed])],
	[[#include <netrom/netrom.h>]])
AC_CHECK_TYPES([struct rose_facilities_struct], [],
	[AC_MSG_ERROR([Both glibc and libax25 are too old or both installed])],
	[[#include <netax25/ax25.h>     /* Or <netrose/rose.h> will blow up */
	#include <netrose/rose.h>
	]])

dnl Checks for header files.
AC_HEADER_DIRENT
m4_warn([obsolete],
[The preprocessor macro `STDC_HEADERS' is obsolete.
  Except in unusual embedded environments, you can safely include all
  ISO C90 headers unconditionally.])dnl
# Autoupdate added the next two lines to ensure that your configure
# script's behavior did not change.  They are probably safe to remove.
AC_CHECK_INCLUDES_DEFAULT
AC_PROG_EGREP

AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(fcntl.h sys/file.h sys/ioctl.h sys/time.h syslog.h termio.h unistd.h)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_OFF_T
m4_warn([obsolete],
[Update your code to rely only on HAVE_SYS_TIME_H,
then remove this warning and the obsolete code below it.
All current systems provide time.h; it need not be checked for.
Not all systems provide sys/time.h, but those that do, all allow
you to include it and time.h simultaneously.])dnl
AC_CHECK_HEADERS_ONCE([sys/time.h])
# Obsolete code to be removed.
if test $ac_cv_header_sys_time_h = yes; then
  AC_DEFINE([TIME_WITH_SYS_TIME],[1],[Define to 1 if you can safely include both <sys/time.h>
	     and <time.h>.  This macro is obsolete.])
fi
# End of obsolete code.

AC_STRUCT_TM

dnl Checks for library functions.
AC_FUNC_MEMCMP
AC_FUNC_UTIME_NULL
AC_FUNC_VPRINTF
AC_CHECK_FUNCS(gettimeofday mktime select socket strdup strerror strspn strstr strtol strtoul uname)


dnl Only use -Wall if we have gcc
if test "x$GCC" = "xyes"; then
  if test -z "`echo "$CFLAGS" | grep "\-Wall" 2> /dev/null`" ; then
    CFLAGS="$CFLAGS -Wall"
  fi
fi

basever=$(echo $PACKAGE_VERSION | sed -e 's@-.*$@@')
AC_SUBST(BASEVERSION, [$basever])
extraver=$(echo $PACKAGE_VERSION | sed -e 's@@<:@^-@:>@*-@@' -e 's@-@_@')
AC_SUBST(EXTRAVERSION, [$extraver])

AC_CONFIG_FILES([call/Makefile ax25ipd/Makefile listen/Makefile Makefile ax25rtd/Makefile ax25mond/Makefile ax25-apps.spec])
AC_OUTPUT
