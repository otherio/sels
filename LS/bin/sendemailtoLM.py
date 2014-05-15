#!/usr/bin/python
# Created by: SELS Team
#
# Description: Sending updates to List Moderator after performing list creation steps.
#
# License: This code is a part of SELS distribution under NCSA/UIUC Open Source License (refer NCSA-license.txt)
############################################################################################################################
import sys
import os
import string
import getopt
import getpass
from SELSLSConfig import *
from SELSProcess import *

def main(arvg=None):
    try:
        input = raw_input("Please select option (1, 2 or 3):\n(1)Send signature verification key to LM\n(2)Send list creator password to LM\n(3)Send update to LM after completing manual steps\n")
        if input =="1":
            lmEmail = raw_input("Enter List Moderator's email: ")
            listname = raw_input("Enter list name: ")
            keysub = "Creating new list %s "%(listname)
            print 'Paste the public key block of the LS admin for signature verification...'
            data =""
            while True:
                line = sys.stdin.readline()
                data = data + line
                if line.startswith("-----END"):
                    break
            msg = "This is the List Server admin's signature verification key. \n"
            msg += "Please save this key as key.asc and import it to your keyring using: \n"
            msg += "gpg --import key.asc \n"
            msg += "or use your client interface to import the key.\n"
            msg = msg + "\n" + data
            sendMail(lmEmail, keysub, msg)
            print "Sending signature verification key"

        elif input == '2':
            lmEmail = raw_input("Enter List Moderator's email: ")
            listname = raw_input("Enter list name: ")
            listPATH = '../lists/' + listname
            subupdate = "List Creator password"
            msgbody1 = " Thankyou for using SELS. The password is : sw4z9bd6"
            msgbody2 = " Use the following password to create a list at http://pkirack1.ncsa.uiuc.edu/mailman/admin"
            msgbody3 = " Please change this password after first use."
            msg = "\n" + msgbody1 + "\n" + msgbody2 + "\n" + msgbody3 + "\n"
            signed = signMsg(msg, listname, listPATH)
            inFile = 'msg.asc'
            outFile = 'encmsg.asc'
            try:
                os.remove(outFile)
            except:
                None

            cmd = 'gpg --always-trust --batch --homedir=%s -a -o %s -r %s -e %s '\
                    %(listPATH, outFile, lmEmail, inFile)
            stdin, stdout, stderr = os.popen3(cmd)
            errmsg = stderr.read()
            outmsg = stdout.read()
            sendMIMEmail(lmEmail, subupdate, outFile)
            print "sending encrypted and signed list creator password"
            stdout.close()
            stderr.close()
        elif input == '3':
            lmEmail = raw_input("Enter List Moderator's email: ")
            listname = raw_input("Enter list name: ")
            listSELSPATH = MAILMAN_LIST_PATH + '/lists/' + listname + '/SELS'
            subupdate = "New list %s created"%(listname)
            msgbody = "\n All steps for list creation are complete. You are ready to generate keys for list %s. \n"%(listname)
            signed = signMsg(msgbody, listname, listSELSPATH)
            outFile = 'msg.asc'
            sendMIMEmail(lmEmail, subupdate, outFile)
            print "sending all manual steps completed email"
        else:
            print "Wrong input. Program will exit now..."
        return 0
    except KeyboardInterrupt:
        print ''
        print '%s' % sys.exc_type
        print 'shutting down'
if __name__ == "__main__":
    sys.exit(main())
