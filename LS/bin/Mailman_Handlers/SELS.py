# Modified by: SELS Team for use with SELS
# License: This code is distributed under GPL License. (refer http://www.gnu.org/copyleft/gpl.html)
############################################################################################################################
# Copyright (C) 2005 by Stefan Schlott
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

"""Decrypt the incoming message using the list key

"""

from Mailman import Errors
from Mailman.Logging.Syslog import syslog
from Mailman import mm_cfg
#from Mailman import GPGUtils
from Mailman import Utils
from SELSsmtphelper import createbounce
from SELSpath import *
from mailmanlogs import *
import GnuPGInterface
import os
import string

#
# subject: Unsubscribe userid listname
#
# subject: Join userid listname
#
# subject: Update listname
#
def process(mlist, msg, msgdata):
    syslog('error', 'sels handler' )
    subject = msg.get('subject', 'no subject')
    sender = msg.get_sender()
    if subject:
        wlist = string.split(subject)
        if ((wlist[0] == 'Join' or wlist[0] == 'Unsubscribe' or \
                wlist[0] == 'Create' or wlist[0] == 'LKpubkey')):
            syslog('error', 'handling....' )
            # save message body to the temporay file
            syslog('error', "subject=" + subject )
            syslog('error', msg.get_payload() )
            msgfile =  MAILMAN_LOG_PATH + '/SELS_msg.txt'
            try:
                fp = open(msgfile, 'w')
                fp.write(msg.get_payload())
                fp.close()
            except IOError:
                syslog('error', "Cannot open msgfile file")
            selslog = MAILMAN_LOG_PATH + "/SELS.log"
            cmd = "python %s/bin/SELSProcess.py -s '%s' -f %s >> %s 2>&1 "%(SELSPATH, subject, msgfile, selslog)
            os.system(cmd);
            raise Errors.DiscardMessage
        elif (len(msg.get_payload()) == 0):
            syslog( 'error', "empty message; message was discarded" )
            raise Errors.DiscardMessage
        else:
            checks(mlist, msg, msgdata, subject, sender)

    else:
        #Check no subject cases too
        subject = ''
        checks(mlist, msg, msgdata, subject, sender)

def checks(mlist, msg, msgdata, subject, sender):
    msgstr = msg.get_payload()
    msgstr = str(msgstr)
    msgstr.strip()
    if msgstr == None:
        add0 = "A message sent by you %s, to list %s is empty"%(mlist.internal_name(), sender)
        add1 = "Dropped Message Subject: "
        emptymsg = add0 +'\n'+ add1 + subject + '\n'
        syslog("error", "Empty message bounced back to user on %s"%(mlist.internal_name()))
        createbounce( emptymsg, mlist, sender)

    # Remove any newlines or whitespace
    msgstr.strip()
    pgpmsg_flag = 0
    pgpsign_flag = 0
    if ('-----BEGIN PGP MESSAGE-----') in msgstr:
        pgpmsg_flag = 1

    if ('-----BEGIN PGP SIGNED MESSAGE-----') in msgstr:
        pgpsign_flag = 1

    if pgpmsg_flag == 0:
        add0 = "A message sent by you on list %s was dropped at the server."%(mlist.internal_name())
        add1 = " This SELS list only allows encrypted OR encrypted and signed messages. Additionally SELS only supports"
        add2 = " PGP MIME encryption and signing for HTML messages and attachments. Please resend."
        add3 = "Dropped Message Subject: "
        plainmsg = add0 + add1 + add2 + '\n'+ add3 + subject + '\n'
        syslog("error"," Plaintext message is being sent on list %s"% (mlist.internal_name()))
        createbounce( plainmsg, mlist, sender)

    elif pgpmsg_flag == 1 and pgpsign_flag ==1:
        add0 = "A message sent by you on list %s was dropped at the server."%(mlist.internal_name())
        add1 = " This message has been signed inline. SELS only supports MIME signed messages"
        add2 = " Please resend."
        add3 = "Dropped Message Subject: "
        signmsg = add0 + add1 + add2 + '\n'+ add3 + subject + '\n'
        syslog("error"," Clearsigned message is being sent on list %s"% (mlist.internal_name()))
        createbounce( signmsg, mlist, sender)

    else:
        syslog("error"," Encrypted message is being sent on list %s"% (mlist.internal_name()))
