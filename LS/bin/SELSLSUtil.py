#!/usr/bin/python
# Created by: SELS Team
#
# Description: Miscellaneous utilities used by SELSProcess.py
#
# License: This code is a part of SELS distribution under NCSA/UIUC Open Source License (refer NCSA-license.txt)
############################################################################################################################
import GnuPGInterface
import threading
import sys
import os
import string
import getopt
import re
import subprocess
from distutils.version import StrictVersion
from SELSLSConfig import *

def execCmd( cmd, input ):
    stdin, stdout, stderr = os.popen3( os.path.normpath(cmd) )
    stdin.write(input)
    stdin.close()
    outmsg = stdout.read()
    errmsg = stderr.read()
    stdout.close()
    stderr.close()

    return outmsg, errmsg


def readLMConfig( listConfigFile ):
    global LM_ID
    global LM_PASS

    listConfigFile = os.path.normpath(listConfigFile)
    try:
        fp = open( listConfigFile, 'r' )
    except IOError, (errno, strerror):
        print "I/O error(%s): %s" % (errno, strerror)

    fbody = fp.read()
    lines = fbody.splitlines()
    for line in lines:
        wlist = string.split(line)
        if wlist[0] == "LM_ID:":
            for i in range (1, len(wlist)):
                if i == 1:
                    LM_ID = wlist[i]
                else:
                    LM_ID = LM_ID + " " + wlist[i]

        if wlist[0] == "LM_PASS:":
            LM_PASS = wlist[1]

def runjava(cmd, stdin=None, stdout=None, stderr=None, blocking=True):
    if stdin == 'pipe': stdin = subprocess.PIPE
    if stdout == 'pipe': stdout = subprocess.PIPE
    if stderr == 'pipe': stderr = subprocess.PIPE
    # Call java via a subprocess
    p = subprocess.Popen(cmd, shell=True, close_fds=True, stdin=stdin, stdout=stdout, stderr=stderr)
    if not blocking: return p
    (stdout, stderr) = p.communicate()
    # Check the return code.
    if p.returncode != 0:
        print stderr
        raise OSError('Java command failed!')
    return (stdout, stderr)

def runjava_in(cmd, prop, blocking=True):
    # Call java with input params via subprocess
    p = subprocess.Popen(cmd, shell=True, close_fds=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.stdin.write(prop)
    if not blocking: return p
    (stdout, stderr) = p.communicate()
    # Check the return code.
    if p.returncode != 0:
        print stderr
        raise OSError('Java command failed!')
        sys.exit()
    return (stdout, stderr)

def checkinstall():
    msg2 = 'For SELS List Server please ensure: \n'
    msg2 += 'Mailman 2.1.5 or higher , '
    msg2 += 'Apache 2.20 or higher , '
    msg2 += 'Python 2.4 or higher , '
    msg2 += 'Java 1.4.x, 1.5.x or 1.6.x, '
    msg2 += 'and GnuPG 1.4.7 '
    osname = os.name
    if osname == 'nt':
        ostype = 'Windows'
    elif osname == 'posix':
        ostype = '*nix (Linux, Unix, Mac OS)'
    stdin, stdout, stderr = os.popen3('java -version')
    errjava = stderr.read()
    outjava = stdout.read()
    stderr.close()
    stdout.close()
    if (errjava == ""):
        if (outjava == ""):
            print msg2
            sys.exit()
        else:
            javaver = outjava
    else:
        javaver = errjava

    jver = javaver.splitlines()
    i = 0
    for line in jver:
        num = string.find(line, 'java version')
        if num == 0 :
            word = jver[i]
        else:
            i = i +1
    stdin, stdout, stderr = os.popen3('gpg --version')
    outgpg = stdout.read()
    stdout.close()
    if (outgpg == ""):
        print msg2
        sys.exit()
    gpgver = outgpg.splitlines()
    stdin, stdout, stderr = os.popen3('python -V')
    errpy = stderr.read()
    stderr.close()
    gpgv = outgpg.splitlines()
    gpgver = gpgv[0].split()
    msg3 = "Warning !! Please install GnuPG version 1.4.7 which has latest security fixes. Using older versions may give errors. "
    msg = 'OS Type = '
    msg += ostype
    msg += '\n'
    msg += word
    msg += '\n'
    msg += gpgv[0]
    msg += '\n'
    msg += errpy
    print '\n'
    print msg
    print msg2
    if StrictVersion(gpgver[2]) < StrictVersion('1.4.7'):
        print '\n'
        print msg3
    else:
        pass

    print '\n'
    sys.exit()

def policycheck():
    # Key generation executables
    cmd = 'java -classpath %s %s' %(BC_CLASSPATH, TESTPOLICY)
    (out1, out2) = runjava(cmd)
