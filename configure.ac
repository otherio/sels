#********************************#
#configure.ac
#Written by: Meenal Pant
#Date:Aug-14-2007
#********************************#
#Prelude
case $target in
*-*-linux*) ;;
*) AC_MSG_ERROR([Linux only, dude!]);;
esac
AC_INIT([sels],[1.1],[sels@ncsa.uiuc.edu] )
AM_INIT_AUTOMAKE([-Wall, -Werror, foreign])
version="1.1"
AC_SUBST(version)
AC_OUTPUT(LS/bin/version.py)
AC_OUTPUT(LM/bin/version.py)
#
if test "$prefix" = "NONE"; then 
	AC_MSG_ERROR([Please provide prefix to install proxyreenc in ~LS/bin. for example: --prefix=/usr/local/sels/LS])
fi

if test "$prefix" = "/usr/local"; then 
	AC_MSG_ERROR([Please provide prefix to install proxyreenc in ~LS/bin. for example: --prefix=/usr/local/sels/LS])
fi
selspath=$prefix
AC_SUBST(selspath)
AC_OUTPUT(LS/bin/Mailman_Handlers/SELSpath.py)
AC_OUTPUT(LS/bin/SELSLSpath.py)
# Configure subdirectories
#AC_CONFIG_SUBDIRS(gpglib)
#Check for programs
AC_PROG_CC
#GPG
AC_PATH_PROG([GPG],[gpg],[:])
if test "$GPG" = ":"; then
  AC_MSG_ERROR([Please install GnuPG 1.4.7])
fi
#Python
AC_PATH_PROG([PYTHON],[python],[:])
if test "$PYTHON" = ":"; then
  AC_MSG_ERROR([Please install the latest version of Python])
fi
#Mutt
AC_PATH_PROG([JAVA], [java], [:])
if test "$JAVA" = ":"; then
  AC_MSG_ERROR([Please install Java 1.4.x, 1.5.x or 1.6.x.])
fi
#Sendmail
AC_PATH_PROG([SENDMAIL], [sendmail],[], [$PATH:/usr/sbin])
if test "$SENDMAIL" = ":"; then
  AC_MSG_ERROR([Please install Sendmail 8.13 or later. Sendmail usually comes bundled with linux/unix distribution.])
fi
#Apache
AC_PATH_PROG([APACHE], [apache],[], [$PATH:/usr/sbin])
if test "$APACHE" = ":"; then
  AC_MSG_ERROR([Please install the latest version of Apache. This is required to run the mailman webserver.])
fi
#Mailman
# if path to mailman is specified by user use that else find it ib default locations 
AC_ARG_WITH([mailman],
       AC_HELP_STRING([--with-mailman=path to mailman lists],
               [Specify location of mailman "lists" directory installation ex: /usr/local/mailman, /var/lib/mailman etc.]),
       mailman=$withval,
       [])
if test "$mailman" = ""; then
  AC_MSG_ERROR([Please install mailman and provide the path where the mailman "lists" folder is located, e.g. ./configure --with-mailman=/usr/local/mailman OR /var/lib/mailman ...etc.])
fi 
#
#Create SELSconfig.py with mailman path
AC_SUBST(mailman)
AC_OUTPUT(LS/bin/SELSconfig.py)
AC_OUTPUT(LS/bin/Mailman_Handlers/mailmanlistpath.py)
#Mailman
# if path to mailman logs is specified by user use that else find it in default locations 
AC_ARG_WITH([mailmanlogs],
       AC_HELP_STRING([--with-mailmanlogs=path to mailman logs],
               [Specify location of mailman "logs" directory installation ex: /var/log/mailman etc.]),
       mailmanlogs=$withval,
       [])
if test "$mailmanlogs" = ""; then
  AC_MSG_ERROR([Please install mailman and provide the path where the mailman "logs" folder is located, e.g. ./configure --with-mailmanlogs=/var/log/mailman])
fi
#
#Create mailmanlogs.py with mailman path
AC_SUBST(mailmanlogs)
AC_OUTPUT(LS/bin/Mailman_Handlers/mailmanlogs.py)
#Check for libraries
#Check for header files
#Check for typedefs,structures and compiler charactersitics
#Check for library functions
#Check for output files
# Configure subdirectories
AC_CONFIG_SUBDIRS(gpglib)
#
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
