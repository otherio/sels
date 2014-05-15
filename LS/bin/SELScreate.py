#!/usr/bin/python
# Created by: SELS Team
#
# Description: Creates SELS keyring inside a mailman list and imports LM public key and List server admin's private key to
#              it.
#
# License: This code is a part of SELS distribution under NCSA/UIUC Open Source License (refer NCSA-license.txt)
############################################################################################################################
import GnuPGInterface
import threading
import sys
import os
import string
import getopt
import shutil
from SELSLSConfig import *
from SELSProcess import *
from SELSLSUtil import *
from version import *

def local(list):
    try:
        print "Creating new list %s local keyring on List Server...\n"%(list)
        listlocalPath = '../lists/' + list
        cmd = "mkdir %s"%(listlocalPath)
        os.system( cmd )

        print 'Paste the public key block sent by LM  to import it for %s signature verification...'%(list)

        data=""
        while True:
            line = sys.stdin.readline()
            data = data + line
            if line.startswith("-----END"):
                break

        pubkeyFile = '%s/LM_pub.asc'%(listlocalPath)
        try:
            fp = open( os.path.normpath(pubkeyFile), 'w')
            fp.write(data)
        except IOError, (errno, strerror):
            print "I/O error(%s): %s" % (errno, strerror)
        else:
            fp.close()

        print "Installing List Server admin's key to list %s keyring on List Server...\n"%(list)

        print 'Paste the private key block of the LS admin for signing...'

        data=""
        while True:
            line = sys.stdin.readline()
            data = data + line
            if line.startswith("-----END"):
                break

        seckeyFile = '%s/Admin_sec.asc'%(listlocalPath)
        try:
            fp = open( os.path.normpath(seckeyFile), 'w')
            fp.write(data)
        except IOError, (errno, strerror):
            print "I/O error(%s): %s" % (errno, strerror)
        else:
            fp.close()

        # install key pairs
        print "install LM public key... %s\n"%(list)
        cmd = 'gpg --homedir=%s --import %s'%(listlocalPath, pubkeyFile)
        stdin, stdout, stderr,  = os.popen3(cmd)
        outmsg = stdout.read()
        errmsg = stderr.read()
        print outmsg
        print errmsg
        stdout.close()
        stderr.close()
        # instal sec key pairs
        print "install LS admin public key... %s\n"%(list)
        cmd = 'gpg --homedir=%s --import %s'%(listlocalPath, seckeyFile)
        stdin, stdout, stderr,  = os.popen3(cmd)
        outmsg = stdout.read()
        errmsg = stderr.read()
        print outmsg
        print errmsg
        stdout.close()
        stderr.close()

    except KeyboardInterrupt:
        print ''
        print '%s' % sys.exc_type
        print 'shutting down'
        sys.exit()

def create( list ):
    try:
        print "Creating new list %s keyring on List Server...\n"%(list)
        listlocalPath = '../lists/' + list
        mailmanlistpath = MAILMAN_LIST_PATH + '/lists/' + list
        if os.path.isdir(os.path.normpath(mailmanlistpath)):
            pass
        else:
            print "List folder %s does not exist... Check to see if your got list creation notification from\
     mailman or check whether the list name you entered is correct.\n"%(mailmanlistpath)
            sys.exit()

        listSELSPath = MAILMAN_LIST_PATH + '/lists/' + list + '/SELS'
        if os.path.isdir(os.path.normpath(listSELSPath)):
            shutil.rmtree(listSELSPath)
        cmd1 = "mkdir %s"%(listSELSPath)
        os.system( cmd1 )
        cmd2 = "mkdir %s/user"%(listSELSPath)
        os.system( cmd2 )
        cmd3 = "chmod g+rw -R %s"%(listSELSPath)
        os.system(cmd3)
        pubkeyFile = '%s/LM_pub.asc'%(listlocalPath)
        seckeyFile = '%s/Admin_sec.asc'%(listlocalPath)
        if os.path.isfile(os.path.normpath(pubkeyFile)):
            # install key pairs
            print "install LM public key... %s\n"%(list)
            installkey(list, pubkeyFile)

            cmd = "chown -Rf mailman:mailman %s"%(listSELSPath)
            os.system( cmd )
            print "Installing LM public key for %s\n"%(list)
        else:
            print "You haven't performed the first step. Start again!"
            sys.exit()

        if os.path.isfile(os.path.normpath(seckeyFile)):
            # install key pairs
            print "install Admin key... %s\n"%(list)
            installkey(list, seckeyFile)

            cmd = "chown -Rf mailman:mailman %s"%(listSELSPath)
            os.system(cmd)

            print "Installing List Server admin's key to list %s keyring on List Server...\n"%(list)
        else:
            print "You haven't performed the first step. Start again!"
            sys.exit()
    except KeyboardInterrupt:
        print ''
        print '%s' % sys.exc_type
        print 'shutting down'
        sys.exit()

def installkey(list, keyfile):
    listSELSPath = MAILMAN_LIST_PATH + '/lists/' + list + '/SELS'

    params = ['--import']

    params.append(keyfile)

    p = gnupg.run(params, create_fhs=['stdout','stderr'])
    t_out = AsyncRead(p.handles['stdout'])
    t_out.start()
    t_err = AsyncRead(p.handles['stderr'])
    t_err.start()
    t_out.join()
    t_err.join()

    plain = t_out.data
    result = t_err.data

    try:
        p.wait()
    except IOError:
        print "Error install key pair: %s\n%s"%(result,plain)
        return None
    return plain
def usage():
    print 'Usage: ./SELScreate.py -l <listname>                  '
    print '       ./SELScreate.py -v (or) --version              '
    print '       ./SELScreate.py -i (or) --installcheck         '
    print '       ./SELScreate.py -p (or) --policyfilecheck      '
    sys.exit()

def version():
    print "The installed SELS version is %s"%(SELSversion)
    sys.exit()

def main(arvg=None):
    try:
        opts, args = getopt.getopt(sys.argv[1:], "vipc:l:u:f:",['version','installcheck','policyfilecheck', 'pubfile=', 'randfile=', 'paramfile='])
    except getopt.GetoptError:
        print "Error: Unrecognized or incomplete option found"
        print ""
        usage()
    except KeyboardInterrupt:
        print '%s' % sys.exc_type
        print 'shutting down'

    file = ""
    user = ""
    list = ""
    subject = ""
    cmd = ""

    for o, v in opts:
        if o in ( "-v", "--version"):
            version()
        if o in ("-i", "--installcheck"):
            checkinstall()
        if o in ("-p", "--policyfilecheck"):
            policycheck()
            sys.exit()
        if o == "-l":
            list = v
        elif o == "-u":
            user = v
        elif o == "-f":
            file = v

    if (list == ""):
        print 'No option provided !'
        usage()
    listlocalPath = '../lists/' + list
    listSELSPath = MAILMAN_LIST_PATH + '/lists/' + list + '/SELS'
    gnupg.options.homedir = listSELSPath

    try:
        input = raw_input("Please select option (1 or 2):\n(1)Create local keyring for list\n(2)Create Mailman keyring for list\n")
        if input =="1":
            local(list)
        elif input =="2":
            create(list)
        else:
            print "Wrong input. Try again\n"

    except KeyboardInterrupt:
        print ''
        print '%s' % sys.exc_type
        print 'shutting down'
        sys.exit()

    return 0

if __name__ == "__main__":
    sys.exit(main())
