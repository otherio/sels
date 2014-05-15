#!/usr/bin/python
# Created by: SELS Team
#
# Description: Miscellaneous utilities used by SELSModerator.py
#
# License: This code is a part of SELS distribution under NCSA/UIUC Open Source License (refer NCSA-license.txt)
############################################################################################################################
import sys
import os
import string
import re
import subprocess
#from subprocess import *
from random import choice
from SELSLMConfig import *
from version import *

def execCmdargs( cmd, input ):
    stdin, stdout, stderr = os.popen3( os.path.normpath(cmd) )

    if input <> None:
        stdin.write(input)
    stdin.close()
    outmsg = stdout.read()
    errmsg = stderr.read()
    stdout.close()
    stderr.close()

    return outmsg, errmsg

def execCmd(cmd):
    stdin, stdout, stderr = os.popen3( os.path.normpath(cmd) )
    outmsg = stdout.read()
    errmsg = stderr.read()

    stdout.close()
    stderr.close()

    return outmsg, errmsg

def runjava(cmd, stdin=None, stdout=None, stderr=None, blocking=True):
    if stdin == 'pipe': stdin = subprocess.PIPE
    if stdout == 'pipe': stdout = subprocess.PIPE
    if stderr == 'pipe': stderr = subprocess.PIPE
    # Call java via a subprocess
    p = subprocess.Popen(cmd, shell=True, stdin=stdin, stdout=stdout, stderr=stderr)
    if not blocking: return p
    (stdout, stderr) = p.communicate()
    # Check the return code.
    if p.returncode != 0:
        print stderr
        raise OSError('Java command failed!')
    return (stdout, stderr)

def runjava_in(cmd, prop, blocking=True):
    # Call java with input params via subprocess
    p = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.stdin.write(prop)
    if not blocking: return p
    (stdout, stderr) = p.communicate()
    # Check the return code.
    if p.returncode != 0:
        print stderr
        raise OSError('Java command failed!')
        sys.exit()
    return (stdout, stderr)

def readLMConfig( listConfigFile, LMconfig ):

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

        if wlist[0] == "LM_SIG_ID:":
            for i in range (1, len(wlist)):
                if i == 1:
                    LM_SIG_ID = wlist[i]
                else:
                    LM_SIG_ID = LM_SIG_ID + " " + wlist[i]

        if wlist[0] == "LM_EMAIL:":
            for i in range (1, len(wlist)):
                if i == 1:
                    LM_EMAIL = wlist[i]
                else:
                    LM_EMAIL = LM_EMAIL + " " + wlist[i]

        if wlist[0] == "LS_ID:":
            for i in range (1, len(wlist)):
                if i == 1:
                    LS_ID = wlist[i]
                else:
                    LS_ID = LS_ID + " " + wlist[i]

        if wlist[0] == "LS_EMAIL:":
            for i in range (1, len(wlist)):
                if i == 1:
                    LS_EMAIL = wlist[i]
                else:
                    LS_EMAIL = LS_EMAIL + " " + wlist[i]
        if wlist[0] == "SMTPDomain:":
            for i in range (1, len(wlist)):
                if i == 1:
                    SMTPDomain = wlist[i]
                else:
                    SMTPDomain = SMTPDomain + " " + wlist[i]
        if wlist[0] == "MySMTPServer:":
            for i in range (1, len(wlist)):
                if i == 1:
                    MySMTPServer = wlist[i]
                else:
                    MySMTPServer = MySMTPServer + " " + wlist[i]
        if wlist[0] == "MySMTPPort:":
            for i in range (1, len(wlist)):
                if i == 1:
                    MySMTPPort = wlist[i]
                else:
                    MySMTPPort = MySMTPPort + " " + wlist[i]


    LMconfig["LM_ID"]=LM_ID
    LMconfig["LM_SIG_ID"]=LM_SIG_ID
    LMconfig["LM_EMAIL"]=LM_EMAIL
    LMconfig["LM_PASS"]=LM_PASS
    LMconfig["LM_SIG_PASS"]=LM_SIG_PASS
    LMconfig["LS_ID"]=LS_ID
    LMconfig["LS_EMAIL"]=LS_EMAIL
    LMconfig["SMTPDomain"]=SMTPDomain
    LMconfig["MySMTPServer"]=MySMTPServer
    LMconfig["MySMTPPort"]=MySMTPPort

def getFingerprint(user):
    params = ['--batch',  '--always-trust', '--fingerprint', '"%s"'%(user)]

    out, err = gnupg.run(params)

    fingerprint=""
    lines = out.splitlines()
    for line in lines:
        if line.find("fingerprint") <> -1:
            wlist=line.split()
            for i in range(3,13):
                fingerprint += wlist[i]
            return fingerprint

    return None

def getkeyid(user):
    finger = getFingerprint(user)
    keyid = finger[32:]
    return keyid

def getsubkeyid(user):
    params = ['--batch',  '--always-trust', '--fingerprint', '"%s"'%(user)]

    out, err = gnupg.run(params)

    fingerprint=""
    lines = out.splitlines()
    for line in lines:
        if line.find("sub") <> -1:
            wlist = line.split()
            sub = wlist[1].partition('/')
            return sub[2]
    return None

def deleteKeyPairs(fingerprint):
    params = ['--batch', '--yes', '--always-trust', '--delete-secret-and-public-key', fingerprint]

    out, err = gnupg.run(params)

def deleteSecretKey(fingerprint):
    params = ['--batch', '--yes', '--always-trust', '--delete-secret-key', fingerprint]

    out, err = gnupg.run(params)


def normUser(user):
    if string.find(user, '<') == -1:
        user = '<' + user + '>'
    return user

def genPass():
    size = 8
    usrpass = ''.join([choice(string.letters + string.digits) for i in range(size)])
    return(usrpass)

def checkinstall():
    msg2 = 'For SELS please ensure: \n'
    msg2 += 'Python 2.4 or higher , '
    msg2 += 'Java 1.4.x, 1.5.x or 1.6.x, '
    msg2 += 'and GnuPG 1.4.7'
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
    if errjava == "":
        javaout = outjava
    else:
        javaout = errjava
    if (javaout == ""):
        print msg2
        sys.exit()
    jver = javaout.splitlines()
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
    msg = '\n'
    msg += 'OS Type = '
    msg += ostype
    msg += '\n'
    msg += word
    msg += '\n'
    msg += gpgver[0]
    msg += '\n'
    msg += errpy
    print msg
    print msg2
    print '\n'
    sys.exit()

def version():
    print "The current SELS version is %s"%(SELSversion)
    sys.exit()

def usage():
    print 'Usage: ./SELSModerator.py -l <listname> <option> '
    print '                               where option is: '
    print '                               --createLMkeys                   (To create List Moderator keys)'
    print '                               --createListkey                  (To create keys for list)'
    print '                               --subscribeUser                  (To subscribe a user)'
    #print '                               --subscribeUser --batch <file>   (Mass Subscription)'
    #print '                               --updatekeys --batch <file>      (Update List key and User Keys)'
    print ''
    print '       ./SELSModerator.py <option> '
    print '                              where option is: '
    print '                              -h or --help'
    print '                              -v or --version'
    print '                              -i or --installcheck'
    print '                              -p or --policyfilecheck'
    sys.exit()

def policycheck():
    # Key generation executables
    print "Checking Java policy files... Please wait!"
    cmd = 'java -classpath %s %s' %(BC_CLASSPATH, TESTPOLICY)
    (out1, out2) = runjava(cmd)

def invalidreg(emailkey):
    """Email validation, checks for syntactically invalid email
    courtesy of Mark Nenadov.
    See http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/65215"""
    emailregex = "^.+\\@(\\[?)[a-zA-Z0-9\\-\\.]+\\.([a-zA-Z]{2,3}|[0-9]{1,3\})(\\]?)$"
    if re.match(emailregex, emailkey) != None:
        return False
    else:
        return True
