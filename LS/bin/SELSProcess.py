#!/usr/bin/python
# Created by: SELS Team
#
# Description: Main processing file for the List Server. Performs key functions like  Transform, List Server key generation,
#              Corresponding key generation.
#
# License: This code is a part of SELS distribution under NCSA/UIUC Open Source License (refer NCSA-license.txt)
############################################################################################################################
import GnuPGInterface
import threading
import sys
import os
import string
import getopt
import smtplib
from email.MIMEText import MIMEText
import socket
import time
import datetime
from SELSLSConfig import *
from SELSLSUtil import *

def readLSConfig( listConfigFile, LSconfig ):
    listConfigFile = os.path.normpath(listConfigFile)
    try:
        fp = open( listConfigFile, 'r' )
        fbody = fp.read()
    except IOError, (errno, strerror):
        print "I/O error(%s): %s" % (errno, strerror)
        sys.exit()
    else:
        fp.close()
    lines = fbody.splitlines()
    for line in lines:
        wlist = string.split(line)
        if wlist[0] == "LK_KEY_ID:":
            LSconfig["LK_KEY_ID"] = wlist[1]

def checkKeyID(list, msgbody, msgfile, user):
    LSconfig={}
    listSELSPath = MAILMAN_LIST_PATH + '/lists/' + list + '/SELS'
    LSconfigFile = listSELSPath + '/list.conf'
    readLSConfig( LSconfigFile, LSconfig)
    # here check the key id if this is encrypted with valid key

    params = ['--list-packets','--always-trust','--batch']
    try:
        print "Check the key id if this is encrypted with valid list key"
        p = gnupg.run(params, create_fhs=['stdin','stdout','stderr'])
        t_out = AsyncRead(p.handles['stdout'])
        t_out.start()
        t_err = AsyncRead(p.handles['stderr'])
        t_err.start()
        p.handles['stdin'].write(msgbody)
        p.handles['stdin'].close()
        t_err.join()
        out = t_out.data
        err = t_err.data
        p.wait()
    except IOError:
        # Control comes here since LK secret key is not stored in key ring
        # Error string contains key id of encryption key
        print err
        msglines = err.splitlines()
        match = False
        for line in msglines:
            if line.find('CRC') <> -1:
                try:
                    fp = open(msgfile, 'w')
                    fp.write("HTML error")
                except IOError:
                    print "Error opening file %s"%(msgfile)
                else:
                    fp.close()
                print "HTML error"
                return False


        for line in msglines:
            if line.startswith("gpg: encrypted with ELG-E key,"):
                wlist = string.split(line)
                print "key id: %s"%(wlist[6])
                # get key id and compare it with LK_KEY_ID

                if wlist[6] == LSconfig["LK_KEY_ID"]:
                    print "key id match!"
                    match = True
                    try:
                        fp = open(msgfile, 'w')
                        fp.write("OK: key id matches -- %s"%(LSconfig["LK_KEY_ID"]))
                    except IOError:
                        print "Error opening file %s"%(msgfile)
                    else:
                        fp.close()

        if match == False:
            try:
                fp = open(msgfile, 'w')
                fp.write("Error: key id does not match -- %s"%(LSconfig["LK_KEY_ID"]))
            except IOError:
                print "Error opening file %s"%(msgfile)
            else:
                fp.close()
                sys.exit()
            print "key id mismatch!"
            return False

        return True


def bouncemsg(list, user, msgbody):
    listSELSPath = MAILMAN_LIST_PATH + '/lists/' + list + '/SELS'
    subjectplain = "Bounce message from List Server Administrator for list %s" %(list)
    signed = signMsg(msgbody, list, listSELSPath)
    file = 'msg.asc'
    sendMIMEmail(user, subjectplain, file)
    print "Sending bounce notification to user %s for list %s"%(user, list)

def transform(list, user, msgbody, msgfile):
    print "================================================================"
    print "Start transform...%s"%(user)
    print msgbody
    print "------------------------------------"

    #
    # apply proxy transformation
    #
    gnupg.call = TRANSFORM
    params = ['--decrypt','--always-trust','--batch']

    # get email addr for corresponding user
    params.append('-r')
    params.append(user)
    gnupg.passphrase=LS_PASS

    # finding finger print for user
    c_email = getEmailAddr( user, True )
    print c_email
    fingerprint = getFingerprint(c_email)
    print fingerprint

    # if there is no corresponding key just return the orignial message
    if fingerprint == None:
        print "Error !! Corresponding keys for user %s do not exist.\n"%(user)
        print "Transformation for user %s failed. User sent bounce message."%(user)
        msg1 = " You will receive an un-transformed message."
        msg2 = " This message was sent to the list %s but failed during SELS Transformation for you."%(list)
        msg3 = " The reason is that a Corresponding keypair for you is not available at the server. "
        msg4 = " Please contact your List Moderator to rectify this problem."
        msgbody = msg1 + msg2 + msg3 + msg4
        bouncemsg(list, user, msgbody)
        return None

    try:
        p = gnupg.run(params, create_fhs=['stdin','stdout','stderr'])
        t_out = AsyncRead(p.handles['stdout'])
        t_out.start()
        t_err = AsyncRead(p.handles['stderr'])
        t_err.start()
        p.handles['stdin'].write(msgbody)
        p.handles['stdin'].close()
        t_out.join()
        t_err.join()
        p.wait()

        ciphertext = t_out.data
        result = t_err.data
        print ciphertext
        print result
        print "Transform success!"
    except IOError:
        print"Error  transforming (decrypting) message: %s\n"%(t_err.data)
        print "Transform failure! Bounce sent to user."
        msg1 = " You will receive an un-transformed message."
        msg2 = " This message was sent to the list %s but failed during SELS Transformation for you."%(list)
        msg3 = " Please contact your List Moderator to rectify this problem."
        msgbody = msg1 + msg2 + msg3
        bouncemsg(list, user, msgbody)
        #try:
        #       fp = open(msgfile, 'w')
        #       fp.write("Transform error")
        #       fp.close()
        #except IOError:
        #        print "Error opening file %s"%(msgfile)
        #       sys.exit()
        return None
    try:
        fp = open(msgfile, 'w')
        fp.write(ciphertext)
    except IOError:
        print "Error opening file %s"%(msgfile)
    else:
        fp.close()

    ciphertext = user + "\n" + ciphertext
    return ciphertext


def process(_cmd, _list, _user, msgbody, secstoexp):

    # first decrypt the message body or check the signature
    plain = decryptMessage(_list, _user, msgbody)

    if plain == None:
        print "signature verification failed!!"
        return
    print "signature verified..."


    if plain == None:
        return

    print plain

    msglines = plain.splitlines()
    gpgmsg = ''
    gpgfind = 0
    cmd = ''
    list = ''
    user = ''
    r = ''
    g = ''
    p = ''
    q = ''
    pubkey = ''
    LMpubkey = ''
    LMEmail = ''
    LKkeyid = ''
    LKprimkeyid = ''

    for line in msglines:

        line = line.strip()

        if gpgfind == 1:
            gpgmsg += line
            gpgmsg += '\n'
            if line.find('-----END' ) <> -1:
                gpgfind = 0
            continue

        wlist = string.split(line)
        if len(wlist) == 0:
            continue
        if wlist[0] == 'cmd:':
            cmd = wlist[1]
        elif wlist[0] == 'list:':
            list = wlist[1]
        elif wlist[0] == 'user:':
            for i in range (1, len(wlist)):
                if i>1:
                    user +=' '
                user += wlist[i]
        elif wlist[0] == 'random:':
            r = wlist[1]
        elif wlist[0] == 'g:':
            g = wlist[1]
        elif wlist[0] == 'p:':
            p = wlist[1]
        elif wlist[0] == 'q:':
            q = wlist[1]
        elif wlist[0] == 'LKkeyid:':
            LKkeyid = wlist[1]
        elif wlist[0] == 'LKprimkeyid:':
            LKprimkeyid = wlist[1]
        elif wlist[0] == 'pubkey:':
            gpgfind = 1
        elif wlist[0] == 'LMpubkey:':
            gpgfind = 1
        elif wlist[0] == 'LMEmail:':
            for i in range (1, len(wlist)):
                if i == 1:
                    LMEmail = wlist[i]
                else:
                    LMEmail = LMEmail + " " + wlist[i]

    print LMEmail

    listSELSPath = MAILMAN_LIST_PATH + '/lists/' + list + '/SELS'

    if cmd == 'Create':
        create(list, g, p, q, LMEmail, secstoexp)
    elif cmd == 'Join':
        gnupg.options.homedir = listSELSPath + '/user'
        pubkey = gpgmsg
        join(list, user, r, pubkey, LMEmail, secstoexp)
    #elif cmd == 'Update':
    #       update(list)
    elif cmd == 'LKpubkey':
        installLKpubkey(list, LKkeyid, LKprimkeyid, LMEmail)

def create( list, g, p, q, LMEmail, secstoexp):
    print "creating new list %s...\n"%(list)
    listSELSPath = MAILMAN_LIST_PATH + '/lists/' + list + '/SELS'
    cmd = "mkdir %s"%(listSELSPath)
    os.system( cmd )

    # save list parameters
    print "save list parameters for %s\n"%(list)
    saveParams(list, g, p, q)

    # generate key pairs
    print "generate LS key pair for %s\n"%(list)
    genLSKeyPair(list, secstoexp)

    # install key pairs
    print "install LS key pair %s\n"%(list)
    installLSKeyPair(list)

    # read LS pub key
    try:
        fp = open('%s/LS_pub.asc'%(listSELSPath), 'r')
        LSpubKey = fp.read()
    except IOError, (errno, strerror):
        print "I/O error(%s): %s" % (errno, strerror)
        sys.exit()
    else:
        fp.close()

    subjectLS = "Public key of LS for list %s"%(list)
    LMEmail = LMEmail.strip('<')
    LMEmail = LMEmail.strip('>')
    signed = signGPGMsg(LSpubKey, list, LMEmail)

    inFile = 'msg.asc'
    outFile = 'encmsg.asc'
    try:
        os.remove(outFile)
    except:
        None

    cmd = 'gpg --always-trust --batch --homedir=%s -a -o %s -r %s -e %s '\
                            %(listSELSPath, outFile, LMEmail, inFile)
    stdin, stdout, stderr = os.popen3(cmd)
    out = stdout.read()
    err = stderr.read()
    print out
    print err
    file = 'encmsg.asc'
    sendMIMEmail(LMEmail, subjectLS, file)
    print "Sending LS pub key to LM"
    stdout.close()
    stderr.close()

def installLKpubkey( list, LKkeyid, LKprimkeyid, LMEmail ):
    listSELSPath = MAILMAN_LIST_PATH + '/lists/' + list + '/SELS'
    configFile =  MAILMAN_LIST_PATH + '/lists/' + list + '/SELS/list.conf'
    lkprimFile = MAILMAN_LIST_PATH + '/lists/' + list + '/SELS/listprime.conf'
    try:
        fp = open(configFile, "w")
        fp.write("LK_KEY_ID: %s\n"%(LKkeyid))
    except IOError, (errno, strerror):
        print "I/O error(%s): %s" % (errno, strerror)
        sys.exit()
    else:
        fp.close()

    try:
        fp = open(lkprimFile, "w")
        fp.write("LK_KEY_ID: %s\n"%(LKprimkeyid))
    except IOError, (errno, strerror):
        print "I/O error(%s): %s" % (errno, strerror)
        sys.exit()
    else:
        fp.close()

    #Send notification to LM
    updatekey = "List Key id received. You are ready to subscribe users."
    subjectLK = " Update for list %s@%s"%(list, SMTPServer)
    LMEmail = LMEmail.strip('<')
    LMEmail = LMEmail.strip('>')
    print LMEmail
    signed = signMsg(updatekey, list, listSELSPath)
    file = 'msg.asc'
    sendMIMEmail(LMEmail, subjectLK, file)
    print "sending LK update"

#Not needed
#def update( list ):
#       listSELSPath = MAILMAN_LIST_PATH + '/lists/' + list + '/SELS'
#       cmd = 'rm -Rf %s/gpg.conf %s/*.gpg*'\
#               %(listSELSPath,listSELSPath)
#
#       os.system( cmd )

def getEmailAddr( user, corresp ):
    user = user.strip()
    wlist = string.split(user)
    email = wlist[len(wlist)-1]

    if email.startswith('<') == False:
        if corresp:
            email = '<C-' + email + '>'
        else:
            email = '<' + email + '>'
    else:
        if corresp:
            email = '<C-' + email[1:len(email)-1] + '>'
        else:
            email = '<' + email[1:len(email)-1] + '>'

    return email

def join( list, user, r, PK_U, LMEmail, secstoexp):
    listSELSPath = MAILMAN_LIST_PATH + '/lists/' + list + '/SELS'
    c_email = getEmailAddr(user, True) # get email id for corresponding user
    email = getEmailAddr(user, False) # get email id for corresponding user

    # delete user pubilc key from key ring files
    fingerprint = getFingerprint( email )
    print fingerprint
    if fingerprint <> None:
        deleteKeyPairs(fingerprint)
    # delete the corresponding key pair from key ring files
    fingerprint = getFingerprint(c_email)
    if fingerprint <> None:
        deleteKeyPairs(fingerprint)

    print "Update for %s of list %s...\n"%(user, list)
    # execute a java program to generate key pairs
    genCUserKeyPair(list, c_email, r, secstoexp)
    # install key pairs
    addKeyPair(list, user, PK_U)
    # Send email to user  about corresponding key gen and installation
    ckeyfile = "Corresponding keys generated at List Server.  Once you %s have installed keys sent by your List Moderator %s, you can  send & receive secure emails on %s@%s"%(email,LMEmail,list, SMTPServer)
    subjectCK = "Step4: Update for user %s of list %s@%s"%(email,list, SMTPServer)
    signed = signMsg(ckeyfile, list, listSELSPath)
    file = 'msg.asc'
    sendMIMEmail(user, subjectCK, file)
    print "sending CK update to user"
    # Send email to LM about  corresponding key gen and installation
    print user
    email = email.strip('<')
    email = email.strip('>')
    print email
    # Send email to LM about corresponding key gen and installation
    ckeymfile = "Corresponding keys for user %s generated at List Server."%(email)
    subjectCKM = "Update for user %s of list %s@%s"%(email,list, SMTPServer)
    LMEmail = LMEmail.strip('<')
    LMEmail = LMEmail.strip('<')
    LMEmail = LMEmail.strip('>')
    print LMEmail
    signed = signMsg(ckeymfile, list, listSELSPath)
    file = 'msg.asc'
    if ( email == LMEmail):
        print "List Moderator is the user. Notification sent already."
        pass
    else:
        sendMIMEmail(LMEmail, subjectCKM, file)
        print "sending CK update to LM"

def signMsg(msg, list, Path):
    listSELSPath = MAILMAN_LIST_PATH + '/lists/' + list + '/SELS'

    gnupg.passphrase = SIG_ID_PASS
    user = SIG_ID

    outFile = 'msg.asc'
    try:
        os.remove(outFile)
    except:
        None

    params = ['--always-trust','--batch']

    params.append('--homedir=%s'%(Path))
    params.append('-a')
    params.append('--clearsign')
    params.append('-o')
    params.append( '%s'%(outFile))

    p = gnupg.run(params, create_fhs=['stdin','stdout','stderr'])
    t_out = AsyncRead(p.handles['stdout'])
    t_out.start()
    t_err = AsyncRead(p.handles['stderr'])
    t_err.start()
    p.handles['stdin'].write(msg)
    p.handles['stdin'].close()
    t_out.join()
    t_err.join()

    plain = t_out.data
    result = t_err.data

    try:
        p.wait()
    except IOError:
        print "Error decrypting message: %s"%(result)
        return None
    return plain

#To remove Mac mail Error where  extra dashes appear on key.
def signGPGMsg(GPGmsg, list, LMEmail):
    listSELSPath = MAILMAN_LIST_PATH + '/lists/' + list + '/SELS'

    gnupg.passphrase = SIG_ID_PASS
    user = SIG_ID
    outFile = 'msg.asc'
    try:
        os.remove(outFile)
    except:
        None

    params = ['--always-trust','--batch']

    params.append('--homedir=%s'%(listSELSPath))
    params.append('-a')
    params.append('--clearsign')
    params.append('--not-dash-escaped')
    params.append('-o')
    params.append( '%s'%(outFile))

    p = gnupg.run(params, create_fhs=['stdin','stdout','stderr'])
    t_out = AsyncRead(p.handles['stdout'])
    t_out.start()
    t_err = AsyncRead(p.handles['stderr'])
    t_err.start()
    p.handles['stdin'].write(GPGmsg)
    p.handles['stdin'].close()
    t_out.join()
    t_err.join()

    plain = t_out.data
    result = t_err.data

    try:
        p.wait()
    except IOError:
        print "Error decrypting message: %s"%(result)
        return None
        sys.exit()
    return plain

def sendMIMEmail( LMEmail, subject, file):
    me = '%s <%s@%s>'%(LS_ID, LS_ID, SMTPServer)
    you = '%s'%(LMEmail )
    try:
        fp = open(file, 'r')
        message= fp.read()
    except IOError:
        print "Error opening file msg.asc"
        sys.exit()
    else:
        fp.close()
    msg = MIMEText(message)
    msg['To'] = you
    msg['Subject'] = subject

    fromaddr = ("From: %s <%s@%s>\n"%(LS_ID, LS_ID,SMTPServer))
    toaddr = (["To: %s\n"%(LMEmail )])


    try:
        # SMTPServer and SMTPPort is defined in SELS_LM_cfg.py
        server = smtplib.SMTP(SMTPServer, SMTPPort)

        refused = server.sendmail( fromaddr,
                toaddr, msg.as_string())

    except smtplib.SMTPRecipientsRefused, e:
        print ('SMTPReceipientRefused exception: ' + str(e))
    except smtplib.SMTPResponseException, e:
        print ('SMTP session failure: %s, %s', e.smtp_code, e.smtp_error)
    except (socket.error), e:
        raise socket.error, e
    except (IOError),e:
        print ('IO Error')
    except (smtplib.SMTPServerDisconnected), e:
        print( 'Server disconnected' )
    except (smtplib.SMTPSenderRefused), e:
        print('Sender refused')
    except (smtplib.SMTPConnectError), e:
        print('SMTP connect error')
    except (smtplib.SMTPDataError), e:
        print ('SMTP data error')

    #except (socket.error), e:
 #       raise socket.error, e
    #except (IOError),e:
 #       print ('IO Error')
    #except (smtplib.SMTPServerDisconnected), e:
 #       print( 'Server disconnected' )
    #except (smtplib.SMTPSenderRefused), e:
 #       print('Sender refused')
    #except (smtplib.SMTPConnectError), e:
 #       print('SMTP connect error')
    #except (smtplib.SMTPDataError), e:
 #       print ('SMTP data error')

    #Remove ascii files
    #msgFile = 'msg.asc'
    #encmsgFile = 'encmsg.asc'
    #if (os.path.isfile(os.path.normpath(msgFile))):
    #                        os.remove(msgFile)
    #if (os.path.isfile(os.path.normpath(encmsgFile))):
    #                        os.remove(encmsgFile)

def sendMail(LMEmail, subject, message):

    me = '%s <%s@%s>'%(LS_ID, LS_ID, SMTPServer)
    you = '%s'%(LMEmail )

    msg = MIMEText(message)
    msg['To'] = you
    msg['Subject'] = subject

    fromaddr = ("From: %s <%s@%s>\n"%(LS_ID, LS_ID,SMTPServer))
    toaddr = (["To: %s\n"%(LMEmail )])

    try:
        # SMTPServer and SMTPPort is defined in SELS_LM_cfg.py
        server = smtplib.SMTP(SMTPServer, SMTPPort)

        refused = server.sendmail( fromaddr,
                toaddr, msg.as_string())

    except smtplib.SMTPRecipientsRefused, e:
        print ('SMTPReceipientRefused exception: ' + str(e))
    except smtplib.SMTPResponseException, e:
        print ('SMTP session failure: %s, %s', e.smtp_code, e.smtp_error)
    except (socket.error), e:
        print ('Socket error')
    except (IOError),e:
        print ('IO Error')
    except (smtplib.SMTPServerDisconnected), e:
        print( 'Server disconnected' )
    except (smtplib.SMTPSenderRefused), e:
        print('Sender refused')
    except (smtplib.SMTPConnectError), e:
        print('SMTP connect error')
    except (smtplib.SMTPDataError), e:
        print ('SMTP data error')

def addLMPubKey(list, LMpubkey):
    listSELSPath = MAILMAN_LIST_PATH + '/lists/' + list + '/SELS'

    try:
        fp = open('%s/LM_pub.asc'%(listSELSPath), 'w')
        fp.write( LMpubkey )
    except IOError, (errno, strerror):
        print "I/O error(%s): %s" % (errno, strerror)
        sys.exit()
    else:
        fp.close()

    params = ['--ignore-time-conflict', '--ignore-valid-from', '--import' ]

    LMpubkeyfile = '%s/LM_pub.asc'%(listSELSPath)
    params.append(LMpubkeyfile)

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
        print "Error adding LM pub key: %s\n%s"%(result,plain)
        return None
        sys.exit()
    return plain

def addKeyPair(list, user, PK_U):
    listSELSPath = MAILMAN_LIST_PATH + '/lists/' + list + '/SELS'
    print "adding key pairs for user %s"%(user)

    email = getEmailAddr(user, False)
    try:
        fp = open('%s/%s_pub.asc'%(listSELSPath,email), 'w')
        fp.write( PK_U )
    except IOError, (errno, strerror):
        print "I/O error(%s): %s" % (errno, strerror)
        sys.exit()
    else:
        fp.close()

    params = ['--ignore-time-conflict', '--ignore-valid-from', '--import' ]

    c_email = getEmailAddr(user, True)
    c_pubkey = '%s/%s_pub.asc'%(listSELSPath,c_email)
    print c_pubkey
    params.append(c_pubkey)

    c_privkey = '%s/%s_secret.asc'%(listSELSPath,c_email)
    print c_privkey
    params.append(c_privkey)

    pubkey = '%s/%s_pub.asc'%(listSELSPath,email)
    print pubkey
    params.append(pubkey)

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
        print "add user key pair: %s\n%s"%(result,plain)
        return None
        sys.exit()

    #Change the permissions of keyring to g+rw so that user can be unsubscribed
    cmd = "chmod g+rw -R %s"%(listSELSPath)
    os.system(cmd)
    #Remove ascii files containing user keys
    if os.path.isfile(os.path.normpath(c_pubkey)):
        os.remove(c_pubkey)
    if os.path.isfile(os.path.normpath(c_privkey)):
        os.remove(c_privkey)
    if os.path.isfile(os.path.normpath(pubkey)):
        os.remove(pubkey)

    return plain

def saveParams(list, g, p, q):
    listSELSPath = MAILMAN_LIST_PATH + '/lists/' + list + '/SELS'
    content = 'g: %s\np: %s\nq: %s\n'%(g, p, q)
    paramfile = listSELSPath+'/params'
    try:
        fp = open(paramfile, 'w')
        fp.write(content)
    except IOError:
        print "Cannot open file %s"%(paramfile)
        sys.exit()
    else:
        fp.close()

def genLSKeyPair(list, secstoexp):
    listSELSPath = MAILMAN_LIST_PATH + '/lists/' + list + '/SELS'
    LS_KEY_ID = "LS(%s@%s) <LS@%s>"%(list, SMTPServer, SMTPServer)
    print LS_KEY_ID
    prop = "type=%s\n"%("LS")
    prop += "listPath=%s\n"%(listSELSPath)
    prop += "userId=%s\n"%(LS_KEY_ID)
    prop += "LSPass=%s\n"%(LS_PASS)
    prop += "expsec=%s\n"%(secstoexp)

    cmd = 'java -classpath %s %s'%(BC_CLASSPATH, KEYGEN)
    runjava_in(cmd, prop)
    #fin, fout=os.popen4(cmd, 'w')
    #fin.write( prop )
    #fin.flush()
    #fin.close()
    #out = fout.read()
    #print out

def installLSKeyPair(list):
    listSELSPath = MAILMAN_LIST_PATH + '/lists/' + list + '/SELS'
    LS_KEY_ID = "LS(%s@%s) <LS@%s>"%(list, SMTPServer, SMTPServer)
    # remove existing key pair
    fingerprint = getFingerprint( "=%s"%(LS_KEY_ID) )
    if fingerprint <> None:
        deleteKeyPairs(fingerprint)

    params = ['--ignore-time-conflict', '--ignore-valid-from', '--import' ]

    pubkey = '%s/LS_pub.asc'%(listSELSPath)
    params.append(pubkey)
    privkey = '%s/LS_secret.asc'%(listSELSPath)
    params.append(privkey)

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
        print "Error install LS key pair: %s\n%s"%(result,plain)
        return None
        sys.exit()
    return plain



def genCUserKeyPair(list, c_user, r, secstoexp):
    listSELSPath = MAILMAN_LIST_PATH + '/lists/' + list + '/SELS'

    prop = "type=%s\n"%("CUSER")
    prop += "listPath=%s\n"%(listSELSPath)
    prop += "userId=%s\n"%(c_user)
    prop += "LSPass=%s\n"%(LS_PASS)
    prop += "randStr=%s\n"%(r)
    prop += "expsec=%s\n"%(secstoexp)

    print prop

    cmd = 'java -classpath %s %s'%(BC_CLASSPATH, KEYGEN)
    runjava_in(cmd, prop)
    #f=os.popen(cmd, 'w')
    #f.write( prop )
    #f.flush()
    #f.close()

def unsubscribe( list, user):
    listSELSPath = MAILMAN_LIST_PATH + '/lists/' + list + '/SELS'
    email = getEmailAddr( user, False )
    #delete user pubilc key from key ring files
    fingerprint = getFingerprint(email)
    print fingerprint
    if fingerprint <> None:
        deleteKeyPairs(fingerprint)
    c_email = getEmailAddr( user, True )
    print c_email
    #delete the corresponding key pair from key ring files
    fingerprint = getFingerprint(c_email)
    print fingerprint
    if fingerprint <> None:
        deleteKeyPairs(fingerprint)
    #Change the permissions of keyring to g+rw so that subsequent users can be subscribed
    cmd = "chmod g+rw -R %s"%(listSELSPath)
    os.system(cmd)

def getFingerprint(user):
    params = ['--batch',  '--always-trust', '--fingerprint']
    params.append(user)

    p = gnupg.run(params, create_fhs=['stdin','stdout','stderr'])
    t_out = AsyncRead(p.handles['stdout'])
    t_out.start()
    t_err = AsyncRead(p.handles['stderr'])
    t_err.start()

    t_out.join()
    t_err.join()

    lines = t_out.data
    result = t_err.data

    try:
        p.wait()
    except IOError:
        return None
        sys.exit()

    fingerprint=""

    print lines
    print result

    lines = lines.splitlines()
    for line in lines:
        if line.find("fingerprint") <> -1:
            wlist=line.split()
            for i in range(3,13):
                fingerprint += wlist[i]
            break
    return fingerprint

def deleteKeyPairs(fingerprint):
    params = ['--batch', '--yes', '--always-trust', '--delete-secret-and-public-key', fingerprint]

    p = gnupg.run(params, create_fhs=['stdin','stdout','stderr'])
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
        print "Error deleting user: %s\n"%[result]
        return None
        sys.exit()

    return plain


def decryptMessage(list, user, msg):
    gnupg.passphrase = LS_PASS
    params = ['--decrypt','--always-trust','--batch']

    print msg

    try:
        p = gnupg.run(params, create_fhs=['stdin','stdout','stderr'])
        t_out = AsyncRead(p.handles['stdout'])
        t_out.start()
        t_err = AsyncRead(p.handles['stderr'])
        t_err.start()
        p.handles['stdin'].write(msg)
        p.handles['stdin'].close()
        t_out.join()
        t_err.join()

        plain = t_out.data
        result = t_err.data
        p.wait()
    except IOError:
        print "Error decrypting message: %s"%(result)
        return None
        sys.exit()

    return plain

def timestamp():
    t = datetime.datetime.now()
    print "Timestamp:%s"%(t)
    return None

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


def main(arvg=None):
    opts, args = getopt.getopt(sys.argv[1:], "l:u:f:s:dbtc")

    file = ""
    user = ""
    list = ""
    subject = ""
    cmd = ""

    for o, v in opts:
        if o == "-l":
            list = v
        if o == "-u":
            user = v
        if o == "-f":
            msgfile = v
        if o == "-s":
            subject = v
        if o == "-t":
            cmd = "Transform"
        if o == "-c":
            cmd = "CheckKeyID"
        if o == "-b":
            cmd = "Bounce"
        if o == "-d":
            cmd = "Delete"
    if subject <> "":
        print "subject: " + subject
        wlist = string.split(subject)

        cmd = wlist[0]
        list = wlist[1]

        if len(wlist) > 2:
            for i in range (3, len(wlist)):
                if i>3:
                    user +=' '
                user += wlist[i]

    print "start of SELSProcess: %s"%(subject)
    if keyexp != "":
        yearstoexp = int(keyexp)
    else:
        yearstoexp = 1
    # not accounting for leap years
    secstoexp = yearstoexp * 365 * 24 * 60 * 60

    listSELSPath = MAILMAN_LIST_PATH + '/lists/' + list + '/SELS'

    if (cmd != "Delete"):
        try:
            fp = open(msgfile, 'r')
            msgbody = fp.read()
        except IOError, (errno, strerror):
            print "I/O error(%s): %s" % (errno, strerror)
            sys.exit()
        else:
            fp.close()

    if (cmd == "Transform"):
        timestamp()
        print user
        gnupg.options.homedir = listSELSPath + '/user'
        transform( list, user, msgbody, msgfile)
    elif (cmd == "CheckKeyID"):
        timestamp()
        checkKeyID( list, msgbody, msgfile, user)
    elif (cmd == "Bounce"):
        timestamp()
        bouncemsg(list, user, msgbody)
    elif (cmd == "Delete"):
        timestamp()
        gnupg.options.homedir = listSELSPath + '/user'
        unsubscribe(list, user)
    else:
        #
        # read the msg body from a temporary file path: f
        # Msg should be text!
        #
        timestamp()
        gnupg.options.homedir = listSELSPath
        process( cmd, list, user, msgbody, secstoexp )

    print "end of SELSProcess"
    os.system('rm *.asc')
    return 0

if __name__ == "__main__":
    sys.exit(main())
