# Created by: SELS Team
#
# Description: LM Configuration file
#
# License: This code is a part of SELS distribution under NCSA/UIUC Open Source License (refer NCSA-license.txt)
############################################################################################################################
import os
import sys
import string
from distutils.version import StrictVersion
# Global variable definition
########################################################################################################################
# Define the key expiration time (in years) for keys related to list. Default = 3 year (Maximum Value at List Server = 5 years)
keyexp = 3
# Define the key size. It is either 1024 or 2048. Default = 1024
keysize = 1024
# Define a Subscriber password for your list subscribers.  You will give this password to each user on your list.
# If you desire a different password for each user, then leave this field blank. The script will generate random
# passwords. The password file can be found at sels-X.X/LM/lists/<listname>/SELS-<listname>.txt. Distribute these
# passwords to susbscribed users.
SubPass = ""
# Define the following terms interactively when you run the script SELSModerator.py with --createLMkeys option.
SMTPDomain = ""
MySMTPServer = ""
MySMTPPort = ""
LM_ID = ""
LM_SIG_ID = ""
LM_EMAIL = ""
LM_PASS = ""
LM_SIG_PASS = ""
LS_ID = ""
LS_SIG_ID = ""
LS_EMAIL = ""
#########################################################################################################################
# SELS supports *nix variants such as linux, Mac OS X and Unix and windows platform
# Determine OS an Java version
osname = os.name
# Check for GnuPG version
stdin, stdout, stderr = os.popen3('gpg --version')
outgpg = stdout.read()
stdout.close()
if (outgpg == ""):
    print "Please install the GnuPG 1.4.7 "
    sys.exit()
gpgv = outgpg.splitlines()
gpgver = gpgv[0].split()
if StrictVersion(gpgver[2]) < StrictVersion('1.4.7'):
    print "Your GnuPG version is %s"%(gpgver[2])
    print "Warning !! Please install GnuPG version 1.4.7 which has latest security fixes. Using older versions may give errors. "
else:
    pass
stdin, stdout, stderr = os.popen3('java -version')
err=stderr.read()
out = stdout.read()
stdout.close()
stderr.close()
if err == "" and out == "":
    print "Please install Java 1.4.x or 1.5.x or 1.6.x"
    sys.exit()

if err =="":
    ver = out.splitlines()

elif out =="":
    ver = err.splitlines()
i = 0
if ( i < 10):
    for line in ver:
        num = string.find(line, 'java version')
        if num == 0 :
            word = ver[i].split()
        else:
            i = i +1

if word != "":
    if word[2][3] == '5':
        javaver= '1.5'
    elif word[2][3] == '4':
        javaver = '1.4'
    elif word[2][3] == '6':
        javaver = '1.6'
    else:
        print 'The version of Java you are using is not supported. \n'
        print 'We currently support Java 1.4, Java 1.5 and Java 1.6 \n'
        sys.exit()
else:
    print "Please install Java 1.4.x or 1.5.x or 1.6.x"
    sys.exit()

if (( osname == 'posix') and ( javaver =='1.4')):
    PLATFORM = 'linux1.4'
elif (( osname == 'posix') and ( javaver =='1.5')):
    PLATFORM = 'linux1.5'
elif (( osname == 'posix') and ( javaver =='1.6')):
    PLATFORM = 'linux1.6'
elif (( osname == 'nt') and ( javaver =='1.4')):
    PLATFORM = 'windows1.4'
elif (( osname == 'nt') and ( javaver =='1.5')):
    PLATFORM = 'windows1.5'
elif (( osname == 'nt') and ( javaver =='1.6')):
    PLATFORM = 'windows1.6'

SELS_PATH = '../..'
LM_PATH = '..'
LIBS = '../../common'
LIB_PATH = os.path.abspath(LIBS)

# Define PATH

if PLATFORM == 'windows1.4': # windows with Java 1.4
    BC_CLASSPATH = "%s/lib/1.4/bcprov-jdk14-130.jar;%s/lib/1.4/bcpg-jdk14-130.zip"%(LIB_PATH, LIB_PATH)
    BC_CLASSPATH += ";%s/lib/junit.jar;%s/lib/1.4/sels-1.4.jar"%(LIB_PATH, LIB_PATH)

elif PLATFORM == 'linux1.4': # *nix with Java 1.4
    BC_CLASSPATH = '%s/lib/1.4/bcprov-jdk14-130.jar:%s/lib/1.4/bcpg-jdk14-130.zip'%(LIB_PATH, LIB_PATH)
    BC_CLASSPATH += ':%s/lib/junit.jar:%s/lib/1.4/sels-1.4.jar'%(LIB_PATH, LIB_PATH)

elif PLATFORM == 'windows1.5': # windows with Java 1.5
    BC_CLASSPATH = "%s/lib/1.5/bcprov-jdk15-133.jar;%s/lib/1.5/bcpg-jdk15-133.jar"%(LIB_PATH, LIB_PATH)
    BC_CLASSPATH += ";%s/lib/junit.jar;%s/lib/1.5/sels-1.5.jar"%(LIB_PATH, LIB_PATH)

elif PLATFORM == 'linux1.5': # *nix with Java 1.5
    BC_CLASSPATH = '%s/lib/1.5/bcprov-jdk15-133.jar:%s/lib/1.5/bcpg-jdk15-133.jar'%(LIB_PATH, LIB_PATH)
    BC_CLASSPATH += ':%s/lib/junit.jar:%s/lib/1.5/sels-1.5.jar'%(LIB_PATH, LIB_PATH)

elif PLATFORM == 'windows1.6': # windows with Java 1.6
    BC_CLASSPATH = "%s/lib/1.6/bcprov-jdk16-137.jar;%s/lib/1.6/bcpg-jdk16-137.jar"%(LIB_PATH, LIB_PATH)
    BC_CLASSPATH += ";%s/lib/junit.jar;%s/lib/1.6/sels-1.6.jar"%(LIB_PATH, LIB_PATH)

elif PLATFORM == 'linux1.6': # *nix with Java 1.6
    BC_CLASSPATH = '%s/lib/1.6/bcprov-jdk16-137.jar:%s/lib/1.6/bcpg-jdk16-137.jar'%(LIB_PATH, LIB_PATH)
    BC_CLASSPATH += ':%s/lib/junit.jar:%s/lib/1.6/sels-1.6.jar'%(LIB_PATH, LIB_PATH)

# Key generation executables
KEYGEN= 'SELSKeyGen'
TESTPOLICY ='testCryptoStrength'

# Python interface to gpg :  GnuPGInterface

import GnuPGInterface

gnupg = GnuPGInterface.GnuPG()
gnupg.options.armor = 1
gnupg.options.meta_interactive = 0
gnupg.options.extra_args.append('--no-secmem-warning')
gnupg.options.quiet = 0
