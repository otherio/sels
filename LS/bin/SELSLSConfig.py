#!/usr/bin/python
# Created by: SELS Team
#
# Description: Configuration file for List Server
#
# License: This code is a part of SELS distribution under NCSA/UIUC Open Source License (refer NCSA-license.txt)
############################################################################################################################
import GnuPGInterface
import threading
import os
import sys
import string
from distutils.version import StrictVersion
from SELSconfig import *
from SELSLSpath import *
# Global variable definition
# Define the key expiration time (in years) for keys related to list. Default = 5 years (maximum value)
keyexp = 5
# Edit and enter the value of the SMTP server (Mailman installation should use this SMTP server)
SMTPServer = "smtp.example.com"
# Edit and enter the value of your SMTPPort
SMTPPort = 25
# Edit and enter the email handle of the List Server Administrator. There must be a signature key pair
# associated with this handle. That will be the List Server's signature key.
LS_ID = SIG_ID = "sels"
# Edit and enter the password for the List Server signature key
SIG_ID_PASS = "password"
# Edit and enter List Server password. This is used during LS key generation.
LS_PASS = "password"
# This value should stay None
LK_KEY_ID = None
############################################################################################################################
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
# SELS List Server supports multiple Java versions
# Determine OS an Java version
osname = os.name
stdin, stdout, stderr = os.popen3('java -version')
err=stderr.read()
out = stdout.read()
stderr.close()
stdout.close()
if err == "" and out == "":
    print "Please install Java 1.4.x or 1.5.x or 1.6.x"
    sys.exit()
if err == "":
    jver = out
elif out == "":
    jver = err
ver = jver.splitlines()
i = 0
if ( i < 10):
    for line in ver:
        num = string.find(line, 'java version')
        if num == 0 :
            word = ver[i].split()
        else:
            i = i +1
else:
    print "Please install Java 1.4.x or 1.5.x or 1.6.x or 1.7.x"
    sys.exit()
if word[2][3] == '5':
    javaver= '1.5'
elif word[2][3] == '4':
    javaver = '1.4'
elif word[2][3] == '6':
    javaver = '1.6'
elif word[2][3] == '7':
    javaver = '1.6'
else:
    print 'The version of Java you are using is not supported. \n'
    print 'We currently only support Java 1.4 - 1.7 \n'
    sys.exit()

if (( osname == 'posix') and ( javaver =='1.4')):
    PLATFORM = 'linux1.4'
elif (( osname == 'posix') and ( javaver =='1.5')):
    PLATFORM = 'linux1.5'
elif (( osname == 'posix') and ( javaver =='1.6')):
    PLATFORM = 'linux1.6'

SELSPATH = SELSLSPATH.rstrip("/LS")
LS_PATH = os.path.abspath(SELSPATH + '/LS')
LIB_PATH = os.path.abspath(SELSPATH + '/common')
if PLATFORM == 'linux1.4': # *nix with Java 1.4
    BC_CLASSPATH = '%s/lib/1.4/bcprov-jdk14-130.jar:%s/lib/1.4/bcpg-jdk14-130.zip'%(LIB_PATH, LIB_PATH)
    BC_CLASSPATH += ':%s/lib/junit.jar:%s/lib/1.4/sels-1.4.jar'%(LIB_PATH, LIB_PATH)
elif PLATFORM == 'linux1.5': # *nix with Java 1.5
    BC_CLASSPATH = '%s/lib/1.5/bcprov-jdk15-133.jar:%s/lib/1.5/bcpg-jdk15-133.jar'%(LIB_PATH, LIB_PATH)
    BC_CLASSPATH += ':%s/lib/junit.jar:%s/lib/1.5/sels-1.5.jar'%(LIB_PATH, LIB_PATH)
elif PLATFORM == 'linux1.6': # *nix with Java 1.6
    BC_CLASSPATH = '%s/lib/1.6/bcprov-jdk16-137.jar:%s/lib/1.6/bcpg-jdk16-137.jar'%(LIB_PATH, LIB_PATH)
    BC_CLASSPATH += ':%s/lib/junit.jar:%s/lib/1.6/sels-1.6.jar'%(LIB_PATH, LIB_PATH)

KEYGEN= 'SELSKeyGen'
TESTPOLICY ='testCryptoStrength'
MAILMAN_LIST_PATH= os.path.abspath(MAILMAN_PATH_VAL)
BIN=  os.path.abspath(LS_PATH +'/bin')
TRANSFORM=  os.path.abspath(BIN +'/proxyreenc')
#############################################################################

gnupg = GnuPGInterface.GnuPG()
gnupg.options.armor = 1
gnupg.options.meta_interactive = 0
gnupg.options.extra_args.append('--no-secmem-warning')
gnupg.options.quiet = 0
gnupg.options.homedir = MAILMAN_LIST_PATH + '/mailman'

class AsyncRead(threading.Thread):
    def __init__(self,infile):
        threading.Thread.__init__(self)
        self.infile=infile
        self.data=None
    def run(self):
        self.data = self.infile.read()
        self.infile.close()

class AsyncWrite(threading.Thread):
    def __init__(self,outfile,data):
        threading.Thread.__init__(self)
        self.outfile=outfile
        self.data=data
    def run(self):
        self.outfile.write(self.data)
        self.outfile.close()
