# Modified by: SELS Team for use with SELS
# License: This code is distributed under GPL License. (refer http://www.gnu.org/copyleft/gpl.html)
############################################################################################################################
# Helper for SMTPDirect.py
import os
import string
#import threading
#from socket import *
from Mailman import Errors
from Mailman.Logging.Syslog import syslog
import GnuPGInterface
from SELSpath import *
from mailmanlogs import *
from mailmanlistpath import *

selslog = MAILMAN_LOG_PATH + "/SELS.log"
selsgpg = MAILMAN_LOG_PATH + "/SELS_GPG_msg.txt"
selsmsg = MAILMAN_LOG_PATH + "/SELS_msg.txt"

def transform(msgbody, mlist, recip):
    lines = msgbody.splitlines()
    #if lines[0].startswith('-----BEGIN PGP MESSAGE-----') == False :
    if '-----BEGIN PGP MESSAGE-----' not in lines:
        syslog ("error", 'Not an encrypted message. Returned to user')
        return msgbody
    msgfile = selsgpg
    try:
        fp = open( msgfile, 'w' )
        fp.write(msgbody)
    except IOError, (errno, strerror):
        print "I/O error(%s): %s" % (errno, strerror)
    else:
        fp.close()

    cmd = "python %s/bin/SELSProcess.py -l %s -u %s -f %s -t >> %s 2>&1"%\
        (SELSPATH, mlist.internal_name(),recip, msgfile, selslog)
    syslog( 'error', cmd )
    os.system(cmd)
    try:
        fp = open( msgfile, 'r' )
        transformed = fp.read()
    except IOError, (errno, strerror):
        print "I/O error(%s): %s" % (errno, strerror)
    else:
        fp.close()
    #if transformed.startswith('Transform'):
    #   return None
    #else:
    return transformed


def checkKeyID(msgbody, mlist, sender, subject):
    if msgbody == None or len(msgbody) == 0:
        return msgbody
    lines = msgbody.splitlines()
    if lines[0].startswith('-----BEGIN PGP MESSAGE-----') == False :
        return msgbody
    msgfile = selsgpg
    try:
        fp = open( msgfile, 'w' )
        fp.write(msgbody)
    except IOError, (errno, strerror):
        print "I/O error(%s): %s" % (errno, strerror)
    else:
        fp.close()

    cmd = "python %s/bin/SELSProcess.py -l %s -f %s -c >> %s 2>&1"%\
        (SELSPATH, mlist.internal_name(), msgfile, selslog)
    syslog( 'error', cmd )
    os.system(cmd)
    try:
        fp = open( msgfile, 'r' )
        result = fp.read()
    except IOError, (errno, strerror):
        print "I/O error(%s): %s" % (errno, strerror)
    else:
        fp.close()
    if result.startswith('Error') or result.startswith('HTML'):
        to = mlist.owner[0]
        add1 = "A message sent by you on list %s was dropped at the server."%(mlist.internal_name())
        if result.startswith('Error'):
            try:
                listconf = MAILMAN_PATH_VAL + '/lists/'+  mlist.internal_name() + '/SELS/listprime.conf'
                fp = open(listconf, 'r')
                lkkeyid = fp.read()
            except IOError, (errno, strerror):
                print "I/O error(%s): %s" % (errno, strerror)
            else:
                fp.close()
            add2 = " Dropped message is encrypted with an incorrect List Key (LK) for list %s."%(mlist.internal_name())
            add3 = " Encrypt with the correct LK key, which has the following key id, and try again:"
            add4 = "%s"%(lkkeyid)
            syslog("error","keyid mismatch on list %s bounced back to user %s"% (mlist.internal_name(),sender))
            add5 = "Dropped Message Subject: "
            bounceLK = add1 + add2  + add3 + '\n' + add4 + '\n'+ '\n' + add5 + str(subject) + '\n'
            createbounce(bounceLK, mlist, sender)
        elif result.startswith('HTML'):
            add2 = " Dropped message was composed as HTML."
            add3 = " SELS only supports PGP MIME encryption for HTML messages and encrypted attachments. Please resend."
            syslog("error","HTML msg without PGP MIME on list %s bounced back to user %s"% (mlist.internal_name(),sender))
            add4 = "Dropped Message Subject: "
            bouncehtml = add1 + add2  + add3 + '\n'+ '\n' + add4 + str(subject) + '\n'
            createbounce(bouncehtml, mlist, sender)

def createbounce(bouncemsg, mlist, sender):
    msgfile = selsmsg
    try:
        fp = open(msgfile, 'w')
        fp.write(bouncemsg)
        fp.close()
    except IOError:
        syslog('error', "Cannot open msgfile file")

    cmd = "python %s/bin/SELSProcess.py -l %s -u %s -f %s -b >> %s 2>&1"%\
                           (SELSPATH, mlist.internal_name(),sender, msgfile, selslog)
    os.system(cmd)
    raise Errors.DiscardMessage

def selscheckkeyid(mlist, msg, msgdata):
    #SELS Checkkeyid begin
    ciphertext = None
    sender = msg.get_sender()
    subject = msg.get('subject', 'no subject')
    #check the id of the message if it's PGP data
    msgcopy = msg
    #Check: Is pgp/mime?
    if (msgcopy.get_content_type()=='multipart/mixed' or \
            (msgcopy.get_content_type()=='multipart/encrypted' and \
            msgcopy.get_param('protocol')=='application/pgp-encrypted') and \
            msgcopy.is_multipart()):
        for submsg in msgcopy.get_payload():
            if submsg.get_content_type()=='multipart/encrypted' and \
            submsg.get_param('protocol')=='application/pgp-encrypted':
                for subsubmsg in submsg.get_payload():
                    if subsubmsg.get_content_type()=='application/octet-stream' or\
                            subsubmsg.get_content_type()=='text/plain':
                        is_pgpmime = True
                        ciphertext=subsubmsg.get_payload()
                        checkKeyID(ciphertext, mlist, sender, subject)
            if submsg.get_content_type()=='application/octet-stream' or \
                    submsg.get_content_type()=='application/pgp-encrypted' or \
                    submsg.get_content_type()=='text/plain':
                ciphertext=submsg.get_payload()
                checkKeyID(ciphertext, mlist, sender, subject)

    if not msgcopy.is_multipart() and (ciphertext==None) and \
            (len(msgcopy.get_payload())>10):
        ciphertext = msgcopy.get_payload()
        checkKeyID(ciphertext, mlist, sender, subject)
    #SELS Checkkeyid end

def selstransform(mlist, recip, msgcopy, msg):
    ciphertext = None
    sender = msg.get_sender()
    subject = msg.get('subject', 'no subject')
    #Check: Is multipart/alternative ?
    if msgcopy.get_content_type()=='multipart/alternative':
        add1 = "A message sent by you on list %s was dropped at the server."%(mlist.internal_name())
        add2 = " Dropped message was composed as HTML."
        add3 = " SELS only supports PGP MIME encryption for HTML messages and encrypted attachments. Please resend."
        syslog("error","HTML msg without PGP MIME on list %s bounced back to user %s"% (mlist.internal_name(),sender))
        add4 = "Dropped Message Subject: "
        bounceoutlook = add1 + add2  + add3 + '\n'+ '\n' + add4 + str(subject) + '\n'
        createbounce(bounceoutlook, mlist, sender)

    #Check: Is pgp/mime?
    if (msgcopy.get_content_type()=='multipart/mixed' or \
        (msgcopy.get_content_type()=='multipart/encrypted' and \
        msgcopy.get_param('protocol')=='application/pgp-encrypted') and \
        msgcopy.is_multipart()):
        for submsg in msgcopy.get_payload():
            if submsg.get_content_type()=='multipart/encrypted' and \
                submsg.get_param('protocol')=='application/pgp-encrypted':
                for subsubmsg in submsg.get_payload():
                    if subsubmsg.get_content_type()=='application/octet-stream' or\
                        subsubmsg.get_content_type()=='text/plain':
                        is_pgpmime = True
                        ciphertext=subsubmsg.get_payload()
                        transformed = transform(ciphertext, mlist, recip)
                        subsubmsg.set_payload(transformed)
            if submsg.get_content_type()=='application/octet-stream' or \
                submsg.get_content_type()=='application/pgp-encrypted' or \
                submsg.get_content_type()=='text/plain':
                ciphertext=submsg.get_payload()
                transformed = transform(ciphertext, mlist, recip)
                submsg.set_payload(transformed)

    if not msgcopy.is_multipart() and (ciphertext==None) and \
        (len(msgcopy.get_payload())>10):
        ciphertext = msgcopy.get_payload()
        transformed = transform(ciphertext, mlist, recip)
        msgcopy.set_payload(transformed)

    return msgcopy
    #SELS transform end
