#!/usr/bin/python
# Created by: SELS Team
#
# Description: Email Utilities used by SELSModerator.py
#
# License: This code is a part of SELS distribution under NCSA/UIUC Open Source License (refer NCSA-license.txt)
############################################################################################################################
import os
import sys
import string
import smtplib
import socket
import getopt
import getpass
#import threading
import time
from SELSLMUtil import *
from SELSLMConfig import * # configuration file

def sendMail( msg, list, user):
    listSELSPath = LM_PATH + '/lists/' + list
    # read list config file
    LMConfig = {}
    listConfigFile = listSELSPath + '/list.conf'
    readLMConfig( listConfigFile, LMConfig )
    LM_ID = LMConfig['LM_ID']
    LM_SIG_ID = LMConfig['LM_SIG_ID']
    LM_PASS = LMConfig['LM_PASS']
    LM_SIG_PASS = LMConfig['LM_SIG_PASS']
    LM_EMAIL = LMConfig['LM_EMAIL']
    LS_ID = LMConfig['LS_ID']
    LS_EMAIL = LMConfig['LS_EMAIL']
    SMTPDomain = LMConfig['SMTPDomain']
    MySMTPServer = LMConfig['MySMTPServer']
    MySMTPPort = LMConfig['MySMTPPort']

    fromaddr = ("From: %s\n"%(LM_EMAIL))
    if user == None:
        toaddr = (["To: %s@%s\n"%(list, SMTPDomain )])
    else:
        toaddr = (["To: %s\n"%(user)])
    try:
        server = smtplib.SMTP(MySMTPServer, int(MySMTPPort))

        refused = server.sendmail( fromaddr,
                toaddr, msg)

    except smtplib.SMTPRecipientsRefused, e:
        print ('SMTP ReceipientRefused exception: ' + str(e))
        print 'Program will exit now !'
        sys.exit()
    except smtplib.SMTPResponseException, e:
        print ('SMTP Session failure: %s, %s', e.smtp_code, e.smtp_error)
        print 'Program will exit now !'
        sys.exit()
    except  socket.error, e:
        print( 'socket error:' + str(e) )
        print 'Program will exit now !'
        sys.exit()
    except IOError, e:
        print( 'IOError:' + str(e))
        print 'Program will exit now!'
        sys.exit()
    except smtplib.SMTPException,e:
        print( 'SMTPException:' + str(e))
        print 'Program will exit now!'
        sys.exit()


def buildAcceptMsg(list, user, pubkey, seckey, LMpubkey, LKpubkey, LSadminkey, LKrevcert ):
    msg = "list: %s\n"%(list)
    msg += "List subscriber: %s\n"%(user)
    msg += "Revocation Certificate for previous List Key(LK) if any:\n%s\n"%(LKrevcert)
    msg += "List subscriber encryption (public) key:\n%s\n"%(pubkey)
    msg += "List subscriber decryption (private) key:\n%s\n"%(seckey)
    #msg += "LMpubkey:\n%s\n"%(LMpubkey)
    msg += "List encryption (public) key:\n%s\n"%(LKpubkey)
    msg += "List Server Administrator\'s signature verification (public) key:\n%s\n"%(LSadminkey)
    return msg

def buildUpdateMsg(list ):
    msg = "cmd: Update\n"
    msg += "list: %s\n"%(list)

    return msg

def buildJoinMsg(list, user, pubkey, rand, email ):
    msg = "cmd: Join\n"
    msg += "list: %s\n"%(list)
    msg += "user: %s\n"%(user)
    msg += "pubkey:\n%s\n"%(pubkey)
    msg += "random: %s\n"%(rand)
    msg += "LMEmail: %s\n"%(email)

    return msg

def buildUnsubscribeMsg(list, user ):
    msg = "cmd: Unsubscribe\n"
    msg += "list: %s\n"%(list)
    msg += "user: %s\n"%(user)

    return msg

def buildCreateListMsg( list, g, p, q, email ):
    msg = "cmd: Create\n"
    msg += "list: %s\n"%(list)
    msg += "g: %s\n"%(g)
    msg += "p: %s\n"%(p)
    msg += "q: %s\n"%(q)
    msg += "LMEmail: %s\n"%(email)

    return msg

def buildLKPubKeyMsg( list, LKkeyid, LKprimkeyid, email ):
    msg = "cmd: LKpubkey\n"
    msg += "list: %s\n"%(list)
    msg += "LKkeyid: %s\n"%(LKkeyid)
    msg += "LKprimkeyid: %s\n"%(LKprimkeyid)
    msg += "LMEmail: %s\n"%(email)

    return msg


def signMsg(msg, list, user, passphrase):
    listSELSPath = LM_PATH + '/lists/' + list
    gnupg.passphrase = passphrase
    inFile = os.path.normpath("%s/msg"%(listSELSPath))
    outFile = os.path.normpath("%s/msg.asc"%(listSELSPath))
    try:
        fp = open( inFile, "w")
        fp.write(msg)
    except IOError, (errno, strerror):
        print "I/O error(%s): %s" % (errno, strerror)
        sys.exit()
    else:
        fp.close()

    try:
        os.remove(outFile)
    except:
        None

    params = ['--always-trust','--batch']
    params.append('-u')
    params.append('"%s"'%(user))
    params.append('--sign')
    params.append( '"%s"'%(inFile))

    signed = None
    try:
        out, err = gnupg.run(params)
        print err
        if err.find("passphrase") <> -1:
            return err
        elif err.find("available") <> -1:
            print 'Signature Key not found in keyring. Either run option --createLMkey again or import the key manually into %s keyring'%(list)
            print ''
            usage()
        else:
            try:
                fp = open(outFile, "r")
                signed = fp.read()
            except IOError, (errno, strerror):
                print "I/O error(%s): %s" % (errno, strerror)
                sys.exit()
            else:
                fp.close()
    except IOError:
        print "Error signing message: %s"%(err)
    try:
        os.remove(inFile)
        os.remove(outFile)
    except:
        None

    return signed

def encMsg(msg, list, user):
    listSELSPath = LM_PATH + '/lists/' + list
    gnupg.passphrase = LM_PASS

    inFile = os.path.normpath("%s/msg"%(listSELSPath))
    outFile = os.path.normpath("%s/msg.asc"%(listSELSPath))
    try:
        fp = open( inFile, "w")
        fp.write(msg)
    except IOError, (errno, strerror):
        print "I/O error(%s): %s" % (errno, strerror)
        sys.exit()
    else:
        fp.close()
    try:
        os.remove(outFile)
    except:
        None

    params = ['--always-trust','--batch', '-r', '"%s"'%(user), '-e']
    params.append( '"%s"'%(inFile))

    signed = None
    out, err = gnupg.run(params)
    try:
        fp = open(outFile, "r")
        signed = fp.read()
    except IOError, (errno, strerror):
        print "I/O error(%s): %s" % (errno, strerror)
        sys.exit()
    else:
        fp.close()
    try:
        os.remove(inFile)
        os.remove(outFile)
    except:
        None

    return signed


def encPassMsg(msg, list, passphrase):
    listSELSPath = LM_PATH + '/lists/' + list
    inFile = os.path.normpath("%s/msg"%(listSELSPath))
    outFile = os.path.normpath("%s/msg.asc"%(listSELSPath))

    try:
        fp = open( inFile, "w")
        fp.write(msg)
    except IOError, (errno, strerror):
        print "I/O error(%s): %s" % (errno, strerror)
        sys.exit()
    else:
        fp.close()
    try:
        os.remove( outFile )
    except:
        None

    gnupg.passphrase = passphrase
    params = ['--always-trust','--batch', "--cipher-algo CAST5" , '-c', '%s'%(inFile)]

    encrypted = None
    try:
        out, err = gnupg.run(params)
        try:
            fp = open(outFile, "r")
            encrypted = fp.read()
        except IOError, (errno, strerror):
            print "I/O error(%s): %s" % (errno, strerror)
            sys.exit()
        else:
            fp.close()
    except IOError:
        print "Error encrypting message: %s"%(err)

    try:
        os.remove(inFile)
        os.remove(outFile)
    except:
        None

    return encrypted

def createList( list, paramfile, config, debugflag ):
    global LM_ID, LM_SIG_ID, LM_PASS, LM_EMAIL, LS_ID, LS_EMAIL, SMTPDomain, MySMTPServer, MySMTPPort
    listSELSPath = LM_PATH + '/lists/' + list
    gnupg.options.homedir = listSELSPath

    LMConfig = {}
    if config == None:
        listConfigFile = listSELSPath + '/list.conf'
        readLMConfig( listConfigFile, LMConfig )
    else:
        LMConfig = config
    LM_ID = LMConfig['LM_ID']
    LM_SIG_ID = LMConfig['LM_SIG_ID']
    LM_PASS = LMConfig['LM_PASS']
    LM_SIG_PASS = LMConfig['LM_SIG_PASS']
    LM_EMAIL = LMConfig['LM_EMAIL']
    LS_ID = LMConfig['LS_ID']
    LS_EMAIL = LMConfig['LS_EMAIL']
    SMTPDomain = LMConfig['SMTPDomain']
    MySMTPServer = LMConfig['MySMTPServer']
    MySMTPPort = LMConfig['MySMTPPort']

    # read El-Gamal parameters, p,g,q
    paramfile = os.path.normpath(paramfile)
    fp = open(paramfile, 'r')
    params = fp.read()
    fp.close()

    params = params.splitlines()
    g = ''
    p = ''
    q = ''

    for line in params:
        line = line.strip()
        wlist = string.split(line)
        if wlist[0] == 'g:':
            g = wlist[1]
        elif wlist[0] == 'p:':
            p = wlist[1]
        elif wlist[0] == 'q:':
            q = wlist[1]

    message = buildCreateListMsg(list, g, p, q, LM_EMAIL)

    # sign a message
    msg = signMsg(message, list, LM_SIG_ID, LM_SIG_PASS )
    while msg.find("passphrase") <> -1:
        print 'Try again!'
        pass1 = getpass.getpass("Enter passphrase for LM signing key: ")
        LMConfig["LM_SIG_PASS"]=pass1
        LM_SIG_PASS = pass1
        msg = signMsg(message, list, LM_SIG_ID, LM_SIG_PASS )

    header = "From: %s\n"%(LM_EMAIL)
    header += "To: %s@%s\n"%(list, SMTPDomain )
    header += "Subject: Create %s\n\n"%(list)
    msg = header + msg + '\n'
    if debugflag:
        print msg
    sendMail( msg, list, None)

    headerls = "From: %s\n"%(LM_EMAIL)
    headerls += "To: %s\n"%(LS_EMAIL)
    headerls += "Subject: List %s created by %s"%(list, LM_EMAIL)
    msgls = headerls + '\n'
    if debugflag:
        print msgls
    sendMail(msgls, list, LS_EMAIL)


def accept( list, user, userpass, pubfile, secfile, LMpubfile, LSadminpubfile, LKpubfile, LKrevcert,config, debugflag ):
    global LM_ID, LM_SIG_ID, LM_PASS, LM_EMAIL, LS_ID, LS_EMAIL, SMTPDomain, MySMTPServer, MySMTPPort
    listSELSPath = LM_PATH + '/lists/' + list
    instrFilePath = LM_PATH+ '/bin/' + 'instructions.txt'

    gnupg.options.homedir = listSELSPath

    LMConfig = {}
    if config == None:
        listConfigFile = listSELSPath + '/list.conf'
        readLMConfig( listConfigFile, LMConfig )
    else:
        LMConfig = config
    LM_ID = LMConfig['LM_ID']
    LM_SIG_ID = LMConfig['LM_SIG_ID']
    LM_PASS = LMConfig['LM_PASS']
    LM_SIG_PASS = LMConfig['LM_SIG_PASS']
    LM_EMAIL = LMConfig['LM_EMAIL']
    LS_ID = LMConfig['LS_ID']
    LS_EMAIL = LMConfig['LS_EMAIL']
    SMTPDomain = LMConfig['SMTPDomain']
    MySMTPServer = LMConfig['MySMTPServer']
    MySMTPPort = LMConfig['MySMTPPort']

    try:
        # read public key of user
        fp = open(os.path.normpath(pubfile), 'r')
        pubkey = fp.read()
        fp.close()

        # read random number from a file for key generation
        fp = open(os.path.normpath(secfile), 'r')
        seckey = fp.read()
        fp.close()

        fp = open(os.path.normpath(LMpubfile), 'r')
        LMpubkey = fp.read()
        fp.close()

        fp = open(os.path.normpath(LSadminpubfile), 'r')
        LSadminkey = fp.read()
        fp.close()

        fp = open(os.path.normpath(LKpubfile), 'r')
        LKpubkey = fp.read()
        fp.close()
    except IOError, (errno, strerror):
        print "I/O error(%s): %s" % (errno, strerror)
        return False
        sys.exit()

    # Instruction email
    try:
        fi = open(instrFilePath, 'r')
        instrbody = fi.read()
    except IOError:
        print 'instructions.txt is missing ! Download code again!'
        sys.exit()
    else:
        fi.close()

    header = "From: %s\n"%(LM_EMAIL)
    header += "To: %s\n"%(user)
    header += "Subject: Step1: Instructions for setting up keys for %s subscribed to %s\n"%(user, list)
    line1 = "You will receive two emails from the List Moderator %s. Please follow the instructions described here.\n"%(LM_EMAIL)
    msg = header + line1 + '\n' + instrbody + '\n'
    if debugflag:
        print msg
    # send to user
    sendMail(msg, list, user)
    time.sleep(1)

    # LM pub email
    line1 = "Import the LM %s public key and place trust in it. "%(LM_EMAIL)
    line2 = "To do so refer to the email sent by %s with subject "%(LM_EMAIL)
    line3 = "\"Instructions for setting up keys for %s subscribed to %s\"\n"%(user, list)

    msg = LMpubkey
    header = "From: %s\n"%(LM_EMAIL)
    header += "To: %s\n"%(user)
    header += "Subject: Step2:  LM public key %s %s\n\n"%(list, user)
    msg = header + line1 + line2 + line3 +'\n' + msg + '\n'

    if debugflag:
        print msg
    # send to user
    sendMail(msg, list, user)
    time.sleep(2)
    # Accept message email
    # build a message
    message = buildAcceptMsg( list, user, pubkey, seckey, LMpubkey, LKpubkey, LSadminkey, LKrevcert)

    # sign a message

    LK_ID = "LK (%s) <%s@%s>"%(list,list,SMTPDomain)
    line4 = "This email contains the list server admin's %s public key, list public key, %s, a revocation certificate, if any, for the previous list public key, and an encryption/decryption key-pair for %s.\n"%(LS_EMAIL, LK_ID, user)
    line5 = "To decrypt this email, you require a passphrase given to you by the List Moderator, %s.\n"%(LM_EMAIL)
    line6 = "To do so refer to the email sent by %s with subject "%(LM_EMAIL)
    line7 = "\"Instructions for setting up keys for %s subscribed to %s\" \n"%(user, list)

    msg = signMsg(message, list, LM_SIG_ID, LM_SIG_PASS)
    while msg.find("passphrase") <> -1:
        print 'Try again!'
        pass1 = getpass.getpass("Enter passphrase for LM signing key: ")
        LMConfig["LM_SIG_PASS"]=pass1
        LM_SIG_PASS = pass1
        msg = signMsg(message, list, LM_SIG_ID, LM_SIG_PASS )

    msg = encPassMsg(msg, list, userpass )
    header = "From: %s\n"%(LM_EMAIL)
    header += "To: %s\n"%(user)
    header += "Subject: Step3:  Accept %s %s\n"%(list, user)
    msg = header + line4 + line5 + line6 + line7 + '\n' +msg + '\n'
    if debugflag:
        print msg
    # send to user
    sendMail(msg, list, user)


def sendToLKPubToLS( list, LKkeyid, LKprimkeyid, config, debugflag ):
    try:
        global LM_ID, LM_SIG_ID, LM_PASS, LM_EMAIL, LS_ID, LS_EMAIL, SMTPDomain, MySMTPServer, MySMTPPort
        listSELSPath = LM_PATH + '/lists/' + list
        gnupg.options.homedir = listSELSPath

        LMConfig = {}
        if config == None:
            listConfigFile = listSELSPath + '/list.conf'
            readLMConfig( listConfigFile, LMConfig )
        else:
            LMConfig = config
        LM_ID = LMConfig['LM_ID']
        LM_SIG_ID = LMConfig['LM_SIG_ID']
        LM_PASS = LMConfig['LM_PASS']
        LM_SIG_PASS = LMConfig['LM_SIG_PASS']
        LM_EMAIL = LMConfig['LM_EMAIL']
        LS_ID = LMConfig['LS_ID']
        LS_EMAIL = LMConfig['LS_EMAIL']
        SMTPDomain = LMConfig['SMTPDomain']
        MySMTPServer = LMConfig['MySMTPServer']
        MySMTPPort = LMConfig['MySMTPPort']

        # build a message
        message = buildLKPubKeyMsg( list, LKkeyid, LKprimkeyid, LM_EMAIL )
        # sign a message
        msg = signMsg(message, list, LM_SIG_ID, LM_SIG_PASS )
        while msg.find("passphrase") <> -1:
            print 'Try again!'
            pass1 = getpass.getpass("Enter passphrase for LM signing key: ")
            LMConfig["LM_SIG_PASS"]=pass1
            LM_SIG_PASS = pass1
            msg = signMsg(message, list, LM_SIG_ID, LM_SIG_PASS )

        header = "From: %s\n"%(LM_EMAIL)
        header += "To: %s@%s\n"%(list, SMTPDomain )
        header += "Subject: LKpubkey %s\n\n"%(list)
        msg = header + msg + '\n'
        if debugflag:
            print msg
        # send to LS
        sendMail(msg, list, None)
    except KeyboardInterrupt:
        print ''
        print '%s' % sys.exc_type
        print 'shutting down'
        sys.exit()

def join( list, user, pubfile, randfile, config, debugflag ):
    global LM_ID, LM_SIG_ID, LM_PASS, LM_EMAIL, LS_ID, LS_EMAIL, SMTPDomain, MySMTPServer, MySMTPPort
    listSELSPath = LM_PATH + '/lists/' + list
    gnupg.options.homedir = listSELSPath

    LMConfig = {}
    if config == None:
        listConfigFile = listSELSPath + '/list.conf'
        readLMConfig( listConfigFile, LMConfig )
    else:
        LMConfig = config
    LM_ID = LMConfig['LM_ID']
    LM_SIG_ID = LMConfig['LM_SIG_ID']
    LM_PASS = LMConfig['LM_PASS']
    LM_SIG_PASS = LMConfig['LM_SIG_PASS']
    LM_EMAIL = LMConfig['LM_EMAIL']
    LS_ID = LMConfig['LS_ID']
    LS_EMAIL = LMConfig['LS_EMAIL']
    SMTPDomain = LMConfig['SMTPDomain']
    MySMTPServer = LMConfig['MySMTPServer']
    MySMTPPort = LMConfig['MySMTPPort']
    # read public key of user
    try:
        fp = open(os.path.normpath(pubfile), 'r')
        pubkey = fp.read()
        fp.close()
    except IOError, (errno, strerror):
        print "I/O error(%s): %s" % (errno, strerror)
        sys.exit()
    # read random number from a file for key generation
    try:
        fp = open(os.path.normpath(randfile), 'r')
        random = fp.read()
        fp.close()
    except IOError, (errno, strerror):
        print "I/O error(%s): %s" % (errno, strerror)
        sys.exit()
    # build a message
    msg = buildJoinMsg( list, user, pubkey, random , LM_EMAIL)
    # sign a message
    msg = encMsg(msg, list, LS_ID )
    while (msg.find('-----BEGIN PGP MESSAGE-----') == -1):
        time.sleep(1)
    header = "From: %s\n"%(LM_EMAIL)
    header += "To: %s@%s\n"%(list, SMTPDomain)
    header += "Subject: Join %s %s\n\n"%(list, user)
    msg = header + msg + '\n'
    if debugflag:
        print msg
    # send to LS
    sendMail(msg, list, None)


def unsubscribe( list, user, config ):
    global LM_ID, LM_SIG_ID, LM_PASS, LM_EMAIL, LS_ID, LS_EMAIL, SMTPDomain, MySMTPServer, MySMTPPort
    listSELSPath = LM_PATH + '/lists/' + list
    gnupg.options.homedir = listSELSPath

    LMConfig = {}
    if config == None:
        listConfigFile = listSELSPath + '/list.conf'
        readLMConfig( listConfigFile, LMConfig )
    else:
        LMConfig = config
    LM_ID = LMConfig['LM_ID']
    LM_SIG_ID = LMConfig['LM_SIG_ID']
    LM_PASS = LMConfig['LM_PASS']
    LM_SIG_PASS = LMConfig['LM_SIG_PASS']
    LM_EMAIL = LMConfig['LM_EMAIL']
    LS_ID = LMConfig['LS_ID']
    LS_EMAIL = LMConfig['LS_EMAIL']
    SMTPDomain = LMConfig['SMTPDomain']
    MySMTPServer = LMConfig['MySMTPServer']
    MySMTPPort = LMConfig['MySMTPPort']
    # build a message
    message = buildUnsubscribeMsg( list, user )
    msg = signMsg( message, list, LM_SIG_ID, LM_SIG_PASS )
    while msg.find("passphrase") <> -1:
        print 'Try again!'
        pass1 = getpass.getpass("Enter passphrase for LM signing key: ")
        LM_SIG_PASS = pass1
        msg = signMsg(message, list, LM_SIG_ID, LM_SIG_PASS )
    header = "From: %s\n"%(LM_EMAIL)
    header += "To: %s@%s\n"%(list, SMTPDomain )
    header += "Subject: Unsubscribe %s %s\n\n"%(list, user)
    msg = header + msg + '\n'
    # build a message
    sendMail(msg, list, None)

def update( list, LMConfig ):
    # build a message
    message = buildUpdateMsg( list)
    msg = signMsg( message, list, LM_SIG_ID, LM_SIG_PASS )
    while msg.find("passphrase") <> -1:
        print 'Try again!'
        pass1 = getpass.getpass("Enter passphrase for LM signing key: ")
        LMConfig["LM_SIG_PASS"]=pass1
        LM_SIG_PASS = pass1
        msg = signMsg(message, list, LM_SIG_ID, LM_SIG_PASS )
    header = "From: %s\n"%(LM_EMAIL)
    header += "To: %s@%s\n"%(list, SMTPDomain )
    header += "Subject: Update %s\n\n"%(list)
    msg = header + msg + '\n'
    # build a message
    sendMail(msg, list, None)

def main(arvg=None):
    global LM_ID, LM_SIG_ID, LM_PASS, LM_EMAIL, LS_ID, LS_EMAIL, SMTPDomain, MySMTPServer, MySMTPPort
    opts, args = getopt.getopt(sys.argv[1:], "c:l:u:f:",\
            ['pubfile=', 'randfile=', 'secfile=', 'paramfile=', 'LMpubfile=', 'LKpubfile='])

    list = ""
    user = ""
    cmd = ""
    pubfile = ""
    randfile = ""
    paramfile = ""

    for o, v in opts:
        if o == "-c":
            cmd = v
        if o == "-l":
            list = v
        if o == "-u":
            user = v
        if o == "--pubfile" :
            pubfile = v
        if o == "--LMpubfile" :
            LMpubfile = v
        if o == "--LKpubfile" :
            LKpubfile = v
        if o == "--secfile" :
            secfile = v
        if o == "--randfile":
            randfile = v
        if o == "--paramfile":
            paramfile = v

    listSELSPath = LM_PATH + '/lists/' + list
    gnupg.options.homedir = listSELSPath
    debugflag = 0
    # read list config file
    LMConfig = {}
    listConfigFile = listSELSPath + '/list.conf'
    readLMConfig( listConfigFile, LMConfig )
    LM_ID = LMConfig['LM_ID']
    LM_SIG_ID = LMConfig['LM_SIG_ID']
    LM_PASS = LMConfig['LM_PASS']
    LM_SIG_PASS = LMConfig['LM_SIG_PASS']
    LM_EMAIL = LMConfig['LM_EMAIL']
    LS_ID = LMConfig['LS_ID']
    LS_EMAIL = LMConfig['LS_EMAIL']
    SMTPDomain = LMConfig['SMTPDomain']
    MySMTPServer = LMConfig['MySMTPServer']
    MySMTPPort = LMConfig['MySMTPPort']

    if cmd == 'join':
        join( list, user, pubfile, randfile, LMConfig, debugflag )
    if cmd == 'accept':
        accept( list, user, pubfile, secfile, LMpubfile, LKpubfile, LMConfig, debugflag )
    elif cmd == 'unsubscribe':
        unsubscribe( list, user, LMConfig )
    elif cmd == 'create':
        createList( list, paramfile, None, LMConfig, debugflag)
    elif cmd == 'update':
        update( list, LMConfig )

    return 0

if __name__ == "__main__":
    sys.exit(main())
