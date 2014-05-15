#!/usr/bin/python
# Created by: SELS Team
#
# Description: SELSModerator.py is used to create keys and subscribe users to a secure email list.
#
# License: This code is a part of SELS distribution under NCSA/UIUC Open Source License (refer NCSA-license.txt)
############################################################################################################################
import sys
import os
import getopt
import getpass
import popen2
import sha
import datetime
import time
import shutil
import glob
from SELSLMConfig import *
from SELSLMUtil import *
from SELSEmailUtil import *

#******Begin Create LM Keys************
def createMetaData(list, SMTPDomain, MySMTPServer, MySMTPPort, LS_EMAIL, testflag):
    try:
        listSELSPath = LM_PATH + '/lists/' + list
        listConfigFile = listSELSPath + '/list.conf'
        lmsigkeyfile = listSELSPath + '/LM_sig_secret.asc'
        lmsigpubkeyfile = listSELSPath + '/LM_sig_pub.asc'

        if os.path.isdir(os.path.normpath(listSELSPath)) and os.path.isfile(os.path.normpath(listConfigFile)) and \
                os.path.isfile(os.path.normpath(lmsigkeyfile)):
            print "List %s already exists. Do you want to configure the list again? (yes/no)"%(list)
            input = raw_input()
            if testflag:
                print '***'+ input

            if input!="yes":
                return False
            else:
                LMConfig = {}
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

        else:
            cmd1 = 'mkdir %s'%(listSELSPath)
            cmd2 = 'mkdir %s/user'%(listSELSPath)
            cmd3 = 'mkdir %s/oldRC'%(listSELSPath)
            cmd4 = 'mkdir %s/prevRC'%(listSELSPath)
            cmd5 = 'mkdir %s/curRC'%(listSELSPath)
            os.system( os.path.normpath(cmd1))
            os.system( os.path.normpath(cmd2))
            os.system( os.path.normpath(cmd3))
            os.system( os.path.normpath(cmd4))
            os.system( os.path.normpath(cmd5))
            osname = os.name
            if (osname == 'posix'):
                dirperm = 'chmod 700 %s'%(listSELSPath)
                os.system( os.path.normpath(dirperm))
                userperm = 'chmod 700 %s/user'%(listSELSPath)
                os.system( os.path.normpath(userperm))
                oldrevperm = 'chmod 700 %s/oldRC'%(listSELSPath)
                os.system( os.path.normpath(oldrevperm))
                prevrevperm = 'chmod 700 %s/prevRC'%(listSELSPath)
                os.system( os.path.normpath(prevrevperm))
                currevperm = 'chmod 700 %s/curRC'%(listSELSPath)
                os.system( os.path.normpath(currevperm))
        try:
            if (MySMTPServer == ""):
                setmysmtp = ""
                print "Your SMTP server is, e.g. smtp.isp.com:"
                setmysmtp = raw_input()
                while setmysmtp == "":
                    print "Input cannot be blank. Try again!"
                    setmysmtp = raw_input()
                MySMTPServer = setmysmtp
            else:
                pass
        except ValueError:
            print 'try again '
            sys.exit()

        try:
            if (MySMTPPort == ""):
                setmyport = ""
                print "Enter the SMTP port for your server e.g. 25 :"
                setmyport = raw_input()
                if setmyport == "":
                    print "Setting the SMTP port to 25"
                    setmyport = 25
                MySMTPPort = setmyport
            else:
                MySMTPPort = 25
                pass
        except ValueError:
            print 'try again'
            sys.exit()

        try:
            if (SMTPDomain == ""):
                setdomain = ""
                print "Enter the List Server's domain name, e.g. ncsa.uiuc.edu:"
                setdomain = raw_input()
                while setdomain == "":
                    print "List Server's domain name cannot be blank. Try again!"
                    setdomain = raw_input()
                SMTPDomain = setdomain
            else:
                pass
        except ValueError:
            print 'try again '
            sys.exit()

        try:
            if (LS_EMAIL == ""):
                setlsemail = ""
                print "Enter the List Server Admin's email e.g. selsadmin@ncsa.uiuc.edu:"
                setlsemail = raw_input()
                while setlsemail == "":
                    print "The List Server Admin's email address cannot be blank. Try again!"
                    setlsemail = raw_input()
                LS_EMAIL = setlsemail
            else:
                pass
        except ValueError:
            print 'try again'
            sys.exit()

        print 'Paste a key block for the List Server Admin\'s public key.'
        print 'You received this key in the first email, with subject "Creating new list %s", from the List Server.'%(list)
        data=""
        while True:
            line = sys.stdin.readline()
            data = data + line
            if line.startswith("-----END"):
                break

        LSadminkeyFile = '%s/LS_admin_verify.asc'%(listSELSPath)
        try:
            fp = open( os.path.normpath(LSadminkeyFile), 'w')
            fp.write(data)
        except IOError:
            print "cannot open file %s to write"%(os.path.normpath(LSadminkeyFile))
            sys.exit()

        else:
            fp.close()
        # clean up directories


        print "Enter E-mail address of your signature key: "
        input = raw_input()

        LM_ID = "LM (%s@%s) <LM@%s>"%(list, SMTPDomain, SMTPDomain)
        if input <> "":
            print 'Paste a key block for your secret signing key to import to keyring for %s...'%(list)
            print 'PLEASE NOTE: Your signature key is simply being installed in the local keyring at \
../lists/%s. This key will not be sent out of your machine by any means, ex: email, etc.\n'%(list)
            data=""
            while True:
                line = sys.stdin.readline()
                data = data + line
                if line.startswith("-----END"):
                    break

            pubkeyFile = '%s/LM_sig_secret.asc'%(listSELSPath)
            try:
                fp = open( os.path.normpath(pubkeyFile), 'w')
                fp.write(data)
            except IOError:
                print "cannot open file %s to write"%(os.path.normpath(pubkeyFile))
                sys.exit()
            else:
                fp.close()

            LM_EMAIL = LM_SIG_ID = normUser(input)
        else:
            print 'List Moderator Encryption key generated for %s  will also be used as the Signature key...'%(list)
            LM_EMAIL = LM_SIG_ID = LM_ID

        LS_ID = "LS(%s@%s) <LS@%s>"%(list,SMTPDomain, SMTPDomain)

        try:
            fp = open( os.path.normpath(listConfigFile), "w")
            fp.write("LM_ID: %s\n"%(LM_ID))
            fp.write("LM_SIG_ID: %s\n"%(LM_SIG_ID))
            fp.write("LM_EMAIL: %s\n"%(LM_EMAIL))
            fp.write("LM_PASS: %s\n"%("None"))
            fp.write("LM_SIG_PASS: %s\n"%("None"))
            fp.write("LS_ID: %s\n"%(LS_ID))
            fp.write("LS_EMAIL: %s\n"%(LS_EMAIL))
            fp.write("SMTPDomain: %s\n"%(SMTPDomain))
            fp.write("MySMTPServer: %s\n"%(MySMTPServer))
            fp.write("MySMTPPort: %s\n"%(MySMTPPort))
            return True

        except IOError:
            print "Cannot open file %s to write " %(os.path.normpath(listConfigFile))
            sys.exit()

        else:
            fp.close()
    except KeyboardInterrupt:
        print ''
        print '%s' % sys.exc_type
        print 'shutting down'
        sys.exit()


# generate El Gamal parameters p,g
def genParams(list, debugflag):
    try:
        listSELSPath = LM_PATH + '/lists/' + list
        prop = "type=%s\n"%("GENPARAMS")
        prop += "listPath=%s\n"%(listSELSPath)
        prop += "keysize=%s\n"%(keysize)

        cmd = 'java -classpath %s %s '%(BC_CLASSPATH, KEYGEN)

        paramFilePath = listSELSPath + '/params'

        if os.path.isfile(os.path.normpath(paramFilePath)):
            print "SELS parameters already exist. Do you want to overwrite? (yes/no)"
            input = raw_input()
            if input!="yes":
                return
        (out1, out2) = runjava_in(cmd, prop)
    except KeyboardInterrupt:
        print ''
        print '%s' % sys.exc_type
        print 'shutting down'
        sys.exit()

def genLMKeyPair(list, debugflag, secstoexp, testflag):
    try:
        listSELSPath = LM_PATH + '/lists/' + list

        # removing List key if it exists
        ListKeyFile = listSELSPath + '/LK_pub.asc'
        if os.path.isfile(os.path.normpath(ListKeyFile)):
            os.remove(os.path.normpath(ListKeyFile))

        pubKeyFile = listSELSPath + '/LM_pub.asc'
        secKeyFile = listSELSPath + '/LM_secret.asc'

        if os.path.isfile(os.path.normpath(pubKeyFile)) and \
               os.path.isfile(os.path.normpath(secKeyFile)):
            print "List Moderator key pair already exists. Do you want to overwrite? (yes/no)"
            input = raw_input()
            if input!="yes":
                return True

        while (True):
            print "Enter password for the private key of list %s. This key is managed by the List Moderator:" %(list)
            if testflag:
                pass1 = raw_input()
                print '****'+pass1
            else:
                pass1 = getpass.getpass()
            print "Enter password for private key of list %s again: " %(list)
            if testflag:
                pass2 = raw_input()
                print '****'+pass2
            else:
                pass2 = getpass.getpass()

            if pass1 == pass2 :
                break
            else:
                print "password mismatch...try again..."



        print 'This task may take a minute ... Please wait '

        prop = "type=%s\n"%("LM")
        prop += "listPath=%s\n"%(listSELSPath)
        prop += "userId=%s\n"%(LM_ID)
        prop += "LMPass=%s\n"%(pass1)
        prop += "expsec=%s\n"%(secstoexp)

        cmd = 'java -classpath %s %s'%(BC_CLASSPATH, KEYGEN)
        (out1, out2) = runjava_in(cmd, prop)
    except KeyboardInterrupt:
        print ''
        print '%s' % sys.exc_type
        print 'shutting down'
        sys.exit()

def installLMEncKeyPair(list, userKeyDir, debugflag):
    try:
        listSELSPath = LM_PATH + '/lists/' + list

        if (userKeyDir):
            gnupg.options.homedir = listSELSPath + '/user'

        params = ['--ignore-time-conflict','--import']

        #remove the previous key rings
        fingerprint = getFingerprint("=%s" %(LM_ID))
        if fingerprint != None:
            deleteKeyPairs(fingerprint)

        pubkey = '%s/LM_pub.asc'%(listSELSPath)
        params.append(pubkey)
        if userKeyDir == False:
            privkey = '%s/LM_secret.asc'%(listSELSPath)
            params.append(privkey)

        out, err = gnupg.run(params)
        if debugflag:
            print err

        try:
            fp = open(os.path.normpath(pubkey))
            LMpubkey = fp.read()
        except IOError, (errno, strerror):
            print "I/O error(%s): %s" % (errno, strerror)
            sys.exit()
        else:
            fp.close()
        if (userKeyDir):
            gnupg.options.homedir = listSELSPath

        return LMpubkey
    except KeyboardInterrupt:
        print ''
        print '%s' % sys.exc_type
        print 'shutting down'
        sys.exit()

def installLMSigKeyPair(list, userKeyDir, debugflag):
    try:
        listSELSPath = LM_PATH + '/lists/' + list

        if (userKeyDir):
            gnupg.options.homedir = listSELSPath + '/user'

        params = [ '--ignore-time-conflict','--import']

        # remove the previous key rings
        fingerprint = getFingerprint("=%s"%(LM_SIG_ID))
        if fingerprint != None:
            deleteKeyPairs(fingerprint)

        pubkey = '%s/LM_sig_pub.asc'%(listSELSPath)
        privkey = '%s/LM_sig_secret.asc'%(listSELSPath)
        lmsigkeyfile = listSELSPath + '/LM_sig_secret.asc'
        lmsigpubkeyfile = listSELSPath + '/LM_sig_pub.asc'
        if os.path.isfile(os.path.normpath(lmsigkeyfile)):
            pass
        else:
            print 'Error! List Moderator Signature Key is not present. Create metadata for %s again.'%(list)
            sys.exit()

        if userKeyDir == True:
            params.append(pubkey)
            out, err = gnupg.run(params)
            if debugflag:
                print err
        else:
            params.append(privkey)
            out, err = gnupg.run(params)
            if debugflag:
                print err

            params = ['--export', '"%s"'%(LM_SIG_ID)]
            out, err = gnupg.run(params)
            if debugflag:
                print err

            pubkey = os.path.normpath(pubkey)
            try:
                fp = open( pubkey, 'w' )
                fp.write(out)
            except IOError:
                print "Cannot open file %s for writing"%(os.path.normpath(pubkey))
                sys.exit()

            else:
                fp.close()
        try:
            fp = open(os.path.normpath(pubkey))
            LMpubkey = fp.read()
        except IOError:
            print "Cannot open file %s for reading"%(os.path.normpath(pubkey))
            sys.exit()

        else:
            fp.close()

        if (userKeyDir):
            gnupg.options.homedir = listSELSPath

        return LMpubkey
    except KeyboardInterrupt:
        print ''
        print '%s' % sys.exc_type
        print 'shutting down'
        sys.exit()


def sendLMEMailToLS(list,LMConfig, debugflag):
    try:
        paramfile = LM_PATH + '/lists/' + list + '/params'
        createList( list, paramfile, LMConfig, debugflag )
        return True

    except KeyboardInterrupt:
        print ''
        print '%s' % sys.exc_type
        print 'shutting down'
        sys.exit()

#******End Create LM Keys************

#******Begin Create List Keys********
def installLSPubkey(list, debugflag):
    try:
        listSELSPath = LM_PATH + '/lists/' + list

        #remove the previous key rings
        fingerprint = getFingerprint("=%s"%(LS_ID))
        if fingerprint != None:
            deleteKeyPairs(fingerprint)

        params = ['--ignore-time-conflict','--import']
        pubkey = '"%s/LS_pub.asc"'%(listSELSPath)

        params.append(pubkey)

        out, err = gnupg.run(params)
        if debugflag:
            print out
        print err
        return True

    except KeyboardInterrupt:
        print ''
        print '%s' % sys.exc_type
        print 'shutting down'
        sys.exit()

def installLKPubkey(list, debugflag):
    try:

        listSELSPath = LM_PATH + '/lists/' + list
        params = ['--ignore-time-conflict','--import']

        #remove the previous key rings
        LK_ID = "LK (%s@%s) <%s@%s>"%(list,SMTPDomain, list,SMTPDomain)
        fingerprint = getFingerprint("=%s"%(LK_ID))
        if fingerprint != None:
            deleteKeyPairs(fingerprint)

        pubkey = '"%s/LK_pub.asc"'%(listSELSPath)
        params.append(pubkey)

        privkey = '%s/rev_secret.asc'%(listSELSPath)
        params.append(privkey)

        try:
            out, err = gnupg.run(params)
        except IOError:
            print "Error install LK key: %s"%(err)
            sys.exit()
        return True

    except KeyboardInterrupt:
        print ''
        print '%s' % sys.exc_type
        print 'shutting down'
        sys.exit()

def signLKPubkey(list, debugflag):
    try:
        gnupg.passphrase = LM_SIG_PASS
        listSELSPath = LM_PATH + '/lists/' + list

        params = ['--yes', '--default-key', '"%s"'%(LM_SIG_ID), '--sign-key', '"%s"'%("LK")]

        try:
            out, err = gnupg.run(params)
        except IOError:
            print "Error signing key: %s"%(err)
        return err
    except KeyboardInterrupt:
        print ''
        print '%s' % sys.exc_type
        print 'shutting down'
        sys.exit()

def exportLKPubkey(list, debugflag):
    try:
        listSELSPath = LM_PATH + '/lists/' + list

        #Exporting Key to send to List Server

        LK_ID = "LK (%s@%s) <%s@%s>"%(list,SMTPDomain,list,SMTPDomain)
        params = ['--export', '"%s"'%(LK_ID)]

        try:
            out, err = gnupg.run(params)
        except IOError:
            print "Error exporting LK pub key: %s"%(err)
            sys.exit()
        if debugflag:
            print err
        pubkeyfile = '%s/LK_pub.asc'%(listSELSPath)
        pubkeyfile = os.path.normpath(pubkeyfile)
        try:
            fp = open( pubkeyfile, 'w' )
            fp.write(out)
        except IOError, (errno, strerror):
            print "I/O error(%s): %s" % (errno, strerror)
            sys.exit()
        else:
            fp.close()
        return out
    except KeyboardInterrupt:
        print ''
        print '%s' % sys.exc_type
        print 'shutting down'
        sys.exit()

def LKGen(list, debugflag, secstoexp, LK_PASS):
    try:
        listSELSPath = LM_PATH + '/lists/' + list
        prop = "type=%s\n"%("LK")
        prop += "listPath=%s\n"%(listSELSPath)
        prop += "userId=LK (%s@%s) <%s@%s>\n"%(list,SMTPDomain, list,SMTPDomain)
        prop += "LKPass=%s\n"%(LK_PASS)
        prop += "expsec=%s\n"%(secstoexp)

        print 'This task may take several minutes ... Please wait'

        cmd = 'java -classpath %s %s'%(BC_CLASSPATH, KEYGEN)
        (out1, out2) = runjava_in(cmd, prop)

    except KeyboardInterrupt:
        print ''
        print '%s' % sys.exc_type
        print 'shutting down'
        sys.exit()

def genRevoke(list, debugflag, LK_PASS):
    listSELSPath = LM_PATH + '/lists/' + list
    oldRevPath = listSELSPath + '/oldRC/'
    prevRevPath = listSELSPath + '/prevRC/'
    curRevPath = listSELSPath + '/curRC'
    curRevCerts = listSELSPath + '/curRC/*.asc'
    prevRevCerts = listSELSPath + '/prevRC/*.asc'

    if os.path.isdir(oldRevPath) and os.path.isdir(prevRevPath) and os.path.isdir(curRevPath):
        pass
    else:
        print "Revocation certificate directory stores do not exist. Please run --createLMKeys option again."
        sys.exit()

    user = "LK"
    fingerprint = getFingerprint("LK")
    LKkeyid = getkeyid("LK")
    today = datetime.datetime.now()
    date = today.date()
    time = today.time()
    for file in glob.glob(prevRevCerts):
        shutil.copy(file, oldRevPath)
        os.remove(file)
    for file in glob.glob(curRevCerts):
        shutil.copy(file , prevRevPath)
        os.remove(file)

    revcertfile = curRevPath + '/%s_%s.asc'%(LKkeyid, date)
    revcertfile = os.path.normpath(revcertfile)

    responses = {
    "[GNUPG:] GET_BOOL gen_revoke.okay" : "y",
    "[GNUPG:] GET_LINE ask_revocation_reason.code" : "1",
    "[GNUPG:] GET_LINE ask_revocation_reason.text" : "",
    "[GNUPG:] GET_BOOL ask_revocation_reason.okay" : "y",
    "[GNUPG:] GET_HIDDEN passphrase.enter" : LK_PASS,
    }
    for prompt in responses.keys():
        responses[prompt.lower()] = responses[prompt]

    try:
        if revcertfile:
            os.remove(revcertfile)
    except:
        pass

    cmd = "gpg -a -o %s  --homedir %s --command-fd 0  --status-fd 1  --gen-revoke %s"%(revcertfile, listSELSPath , LKkeyid)
    o, inp = popen2.popen4(cmd)
    counter = 20
    while counter > 0:
        counter -= 1;
        line = o.readline().strip()
        if len(line) == 0:
            continue;
        if ((line.find("[GNUPG:]") != 0) and debugflag):
            print line
        for prompt in responses.keys():
            if line.lower().find(prompt) >= 0:
                response = responses[prompt]
                inp.write(response + "\n")
                inp.flush()
                break;
    inp.close()
    o.close()
    return True

#******End Create List Keys**********

#******Begin Subscribe User Keys*****
def genUserKeyPair(list, subuser, servuser, userPass, debugflag, batchflag, secstoexp):
    try:
        print 'This task may take a minute ... Please wait '
        listSELSPath = LM_PATH + '/lists/' + list
        subuserIdHash = sha.new(subuser).hexdigest()
        servuserIdHash = sha.new(servuser).hexdigest()

        #pubKeyFile = listSELSPath + '/%s_pub.asc'%(subuserIdHash)
        #secKeyFile = listSELSPath + '/%s_secret.asc'%(subuserIdHash)

        prop = "type=%s\n"%("USER")
        prop += "listPath=%s\n"%(listSELSPath)
        prop += "subuserId=%s\n"%(subuser)
        prop += "servuserId=%s\n"%(servuser)
        prop += "subuserIdHash=%s\n"%(subuserIdHash)
        prop += "servuserIdHash=%s\n"%(servuserIdHash)
        prop += "LMPass=%s\n"%(LM_PASS)
        prop += "userPass=%s\n"%(userPass)
        prop += "expsec=%s\n"%(secstoexp)

        cmd = 'java -classpath %s %s'%(BC_CLASSPATH, KEYGEN)
        out, err = execCmdargs(cmd, prop)
        if( err.find("PGPException") <> -1):
            #print err
            print "Wrong Passphrase ! Try again. "
            return err
        elif( err != ""):
            print err
            raise OSError('Java command failed!')
            sys.exit()
            return None
    except KeyboardInterrupt:
        print ''
        print '%s' % sys.exc_type
        print 'shutting down'
        sys.exit()


def installUserPubkey(list, user, usertype, debugflag):
    try:
        listSELSPath = LM_PATH + '/lists/' + list
        gnupg.options.homedir = listSELSPath
        # remove existing key pair
        fingerprint = getFingerprint("=%s"%(user))
        if fingerprint != None:
            deleteKeyPairs(fingerprint)

        params = ['--ignore-time-conflict','--import']
        if usertype == True: # Subscriber pub key for sub
            pubkey = '"%s/%s_subpub.asc"'%(listSELSPath, sha.new(user).hexdigest())
        else:
            pubkey = '"%s/%s_servpub.asc"'%(listSELSPath, sha.new(user).hexdigest())

        params.append(pubkey)

        out, err = gnupg.run(params)

    except KeyboardInterrupt:
        print ''
        print '%s' % sys.exc_type
        print 'shutting down'
        sys.exit()

def signUserPubkey(list, user, debugflag):
    try:
        gnupg.passphrase = LM_SIG_PASS
        listSELSPath = LM_PATH + '/lists/' + list
        params = ['--yes', '--default-key', '"%s"'%(LM_SIG_ID), '--sign-key', '"%s"'%(user)]
        out, err = gnupg.run(params)
        return err
    except KeyboardInterrupt:
        print ''
        print '%s' % sys.exc_type
        print 'shutting down'
        sys.exit()

# The following "User" functions are not being used due to rollback for PGP Desktop.

def installUserkey(list, user):
    listSELSPath = LM_PATH + '/lists/' + list
    listSELSUserPath = LM_PATH + '/lists/' + list + '/user/'
    gnupg.options.homedir = listSELSPath
    # remove existing key pair
    fingerprint = getFingerprint("=%s"%(user))
    if fingerprint != None:
        deleteKeyPairs(fingerprint)

    params = ['--ignore-time-conflict', '--import', '--allow-secret-key']
    pubkey = '"%s/%s_pub.asc"'%(listSELSPath, sha.new(user).hexdigest())
    seckey = '"%s/%s_secret.asc"'%(listSELSPath, sha.new(user).hexdigest())
    params.append(pubkey)
    params.append(seckey)
    out, err = gnupg.run(params)

    flag = 1
    if flag:
        gnupg.options.homedir = listSELSUserPath
        # remove existing key pair
        fingerprint = getFingerprint("=%s"%(user))
        if fingerprint != None:
            deleteKeyPairs(fingerprint)
        params2 = ['--ignore-time-conflict', '--import', '--allow-secret-key']
        params2.append(pubkey)
        params2.append(seckey)
        out, err = gnupg.run(params2)

def exportSecSubkey(list, user):
    try:
        listSELSPath = LM_PATH + '/lists/' + list
        gnupg.options.homedir = listSELSPath
        params = ['--export-secret-subkey', '"%s"'%(user)]
        out, err = gnupg.run(params)
        seckeyfile = '%s/%s_secret_subkey.asc'%(listSELSPath, sha.new(user).hexdigest())
        seckeyfile = os.path.normpath(seckeyfile)
        try:
            if seckeyfile:
                os.remove(seckeyfile)
        except:
            pass
        try:
            fp = open( seckeyfile, 'w' )
            fp.write(out)
        except IOError, (errno, strerror):
            print "I/O error(%s): %s" % (errno, strerror)
            sys.exit()
        else:
            fp.close()

    except KeyboardInterrupt:
        print ''
        print '%s' % sys.exc_type
        print 'shutting down'
        sys.exit()


def installSecSubkey(list, user):
    listSELSPath = LM_PATH + '/lists/' + list
    gnupg.options.homedir = listSELSPath

    # remove existing key pair
    fingerprint = getFingerprint("=%s"%(user))
    if fingerprint != None:
        deleteKeyPairs(fingerprint)

    params = ['--ignore-time-conflict', '--import', '--allow-secret-key']
    seckey = '"%s/%s_secret_subkey.asc"'%(listSELSPath, sha.new(user).hexdigest())
    params.append(seckey)

    out, err = gnupg.run(params)


def signSecSubkey(list, user):
    listSELSPath = LM_PATH + '/lists/' + list
    gnupg.options.homedir = listSELSPath
    gnupg.passphrase = LM_SIG_PASS
    params = ['--yes', '--default-key', '"%s"'%(LM_SIG_ID), '--sign-key', '"%s"'%(user)]
    out, err = gnupg.run(params)
    return err

def exportUserSeckey(list, user):
    try:
        listSELSPath = LM_PATH + '/lists/' + list
        gnupg.options.homedir = listSELSPath
        params = ['--export-secret-key', '"%s"'%(user)]
        out, err = gnupg.run(params)
        seckeyfile = '%s/%s_secret.asc'%(listSELSPath, sha.new(user).hexdigest())
        seckeyfile = os.path.normpath(seckeyfile)
        try:
            if seckeyfile:
                os.remove(seckeyfile)
        except:
            pass
        try:
            fp = open( seckeyfile, 'w' )
            fp.write(out)
        except IOError, (errno, strerror):
            print "I/O error(%s): %s" % (errno, strerror)
            sys.exit()
        else:
            fp.close()
    except KeyboardInterrupt:
        print ''
        print '%s' % sys.exc_type
        print ' shutting down'
        sys.exit()

def NOTexportUserPubkey(list,user, debugflag):
    try:
        listSELSPath = LM_PATH + '/lists/' + list
        gnupg.options.homedir = listSELSPath

        params = ['--export', '"%s"'%(user)]
        out, err = gnupg.run(params)
        pubkeyfile = '%s/%s_pub.asc'%(listSELSPath, sha.new(user).hexdigest())
        pubkeyfile = os.path.normpath(pubkeyfile)
        try:
            if pubkeyfile:
                os.remove(pubkeyfile)
        except:
            pass
        try:
            fp = open( pubkeyfile, 'w' )
            fp.write(out)
        except IOError, (errno, strerror):
            print "I/O error(%s): %s" % (errno, strerror)
            sys.exit()
        else:
            fp.close()

    except KeyboardInterrupt:
        print ''
        print '%s' % sys.exc_type
        print ' shutting down'
        sys.exit()

def addemailUserkey (list, userkeyid, userName, userPass, UserEmail, debugflag):
    listSELSPath = LM_PATH + '/lists/' + list + '/user'
    name = userName
    email = UserEmail
    comment = userName
    password = userPass

    cmd = "gpg --homedir %s --command-fd 0  --status-fd 1  --edit-key %s"%( listSELSPath, userkeyid)

    o, inp = popen2.popen4(cmd)
    print o
    print inp

    counter = 30
    while counter > 0:
        counter -= 1;
        line = o.readline().strip()
        print line
        if len(line) == 0:
            continue;
        if line.find("[GNUPG:]") != 0 and debugflag:
            print line
        if line.find ("[GNUPG:] GET_LINE keyedit.prompt")  !=0 :
            answer = "adduid"
            inp.write(answer + "\n")
            inp.flush()
        if line.find ("[GNUPG:] GET_LINE keygen.name")  !=0 :
            answer = name
            inp.write(answer + "\n")
            inp.flush()
        if line.find ("[GNUPG:] GET_LINE keygen.email")  !=0 :
            answer = email
            inp.write(answer + "\n")
            inp.flush()
        if line.find ("[GNUPG:] GET_LINE keygen.comment")  !=0 :
            answer = comment
            inp.write(answer + "\n")
            inp.flush()
        if line.find ("[GNUPG:] GET_HIDDEN passphrase.enter")  !=0 :
            answer = password
            inp.write(answer + "\n")
            inp.flush()
        if line.find ("[GNUPG:] GET_LINE keyedit.prompt")  !=0 :
            answer = "uid 2"
            inp.write(answer + "\n")
            inp.flush()
        if line.find ("[GNUPG:] GET_LINE keyedit.prompt")  !=0 :
            answer = "primary"
            inp.write(answer + "\n")
            inp.flush()
        if line.find ("[GNUPG:] GET_HIDDEN passphrase.enter")  !=0 :
            answer = password
            inp.write(answer + "\n")
            inp.flush()
        if line.find ("[GNUPG:] GET_LINE keyedit.prompt")  !=0 :
            answer = "save"
            inp.write(answer + "\n")
            inp.flush()

    inp.close()
    o.close()

def deloneuid(list, userkeyid, debugflag):
    listSELSPath = LM_PATH + '/lists/' + list + '/user/'
    cmd = "gpg --homedir %s --command-fd 0  --status-fd 1  --edit-key %s"%( listSELSPath, userkeyid)
    o, inp = popen2.popen4(cmd)
    counter = 30
    while counter > 0:
        counter -= 1;
        line = o.readline().strip()
        if len(line) == 0:
            continue;
        if line.find("[GNUPG:]") != 0 and debugflag:
            print line
        if line.find ("[GNUPG:] GET_LINE keyedit.prompt")  !=0 :
            answer = "uid 2"
            inp.write(answer + "\n")
            inp.flush()
        if line.find ("[GNUPG:] GET_LINE keyedit.prompt")  !=0 :
            answer = "deluid"
            inp.write(answer + "\n")
            inp.flush()
        if line.find ("[GNUPG:] GET_LINE keyedit.prompt") or ("[GNUPG:] GET_BOOL keyedit.remove.uid.okay") !=0 :
            answer = "y"
            inp.write(answer + "\n")
            inp.flush()
        if line.find ("[GNUPG:] GET_LINE keyedit.prompt")  !=0 :
            answer = "save"
            inp.write(answer + "\n")
            inp.flush()
    inp.close()
    o.close()

def exportUserLSPubkey(list, user, userkeyid, debugflag):
    try:
        listSELSUserPath = LM_PATH + '/lists/' + list + '/user/'
        params = [ '--homedir', '"%s"'%(listSELSUserPath) ,'--export', '"%s"'%(userkeyid)]
        out, err = gnupg.run(params)
        LSpubkeyfile = '%s%s_LS_pub.asc'%(listSELSUserPath, sha.new(user).hexdigest())
        LSpubkeyfile = os.path.normpath(LSpubkeyfile)
        try:
            if LSpubkeyfile:
                os.remove(LSpubkeyfile)
        except:
            pass
        try:
            fp = open( LSpubkeyfile, 'w' )
            fp.write(out)
        except IOError, (errno, strerror):
            print "I/O error(%s): %s" % (errno, strerror)
            sys.exit()
        else:
            fp.close()

    except KeyboardInterrupt:
        print ''
        print '%s' % sys.exc_type
        print ' shutting down'
        sys.exit()

# The above "User" functions are not being used due to rollback for PGP Desktop.

def exportUserPubkey(list,user, usertype, debugflag):
    try:
        listSELSPath = LM_PATH + '/lists/' + list
        params = ['--yes', '--default-key', '"%s"'%(LM_SIG_ID), '--sign-key', '"%s"'%(user)]
        params = ['--export', '"%s"'%(user)]
        out, err = gnupg.run(params)
        if usertype == True: # subuser
            pubkeyfile = '%s/%s_subpub.asc'%(listSELSPath,sha.new(user).hexdigest())
        else:
            pubkeyfile = '%s/%s_servpub.asc'%(listSELSPath,sha.new(user).hexdigest())

        pubkeyfile = os.path.normpath(pubkeyfile)
        try:
            fp = open( pubkeyfile, 'w' )
            fp.write(out)
        except IOError, (errno, strerror):
            print "I/O error(%s): %s" % (errno, strerror)
        else:
            fp.close()

    except KeyboardInterrupt:
        print ''
        print '%s' % sys.exc_type
        print 'shutting down'
        sys.exit()

def deleteUserkey(list, user):
    listSELSPath = LM_PATH + '/lists/' + list
    gnupg.options.homedir = listSELSPath

    # remove user pub key in list directory. user pub key is installed in user dir
    fingerprint = getFingerprint("%s"%(user))
    if fingerprint != None:
        deleteKeyPairs(fingerprint)
    listSELSUserPath = LM_PATH + '/lists/' + list + '/user/'
    flag =1
    if flag:
        gnupg.options.homedir= listSELSUserPath
        deleteKeyPairs(fingerprint)

def sendEMailToLS(list, user, userEmail,  LMConfig, debugflag):
    try:
        pubfile = LM_PATH + '/lists/' + list + '/%s_servpub.asc'%(sha.new(user).hexdigest())
        randfile = LM_PATH + '/lists/' + list + '/random'
        join(list, userEmail, pubfile, randfile, LMConfig, debugflag)
    except KeyboardInterrupt:
        print ''
        print '%s' % sys.exc_type
        print 'shutting down'
        sys.exit()


def sendEMailToUser(list, user, userEmail, userpass, LMConfig, debugflag ):
    try:
        pubfile = LM_PATH + '/lists/' + list + '/%s_subpub.asc'%(sha.new(user).hexdigest())
        secfile = LM_PATH + '/lists/' + list + '/%s_subsecret.asc'%(sha.new(user).hexdigest())
        if LM_ID <> LM_SIG_ID:
            LMpubfile = LM_PATH + '/lists/' + list + '/LM_sig_pub.asc'
        else:
            LMpubfile = LM_PATH + '/lists/' + list + '/LM_pub.asc'
        LKpubfile = LM_PATH + '/lists/' + list + '/LK_pub.asc'
        LSadminpubfile = LM_PATH + '/lists/' + list + '/LS_admin_verify.asc'
        prevRevCert = LM_PATH + '/lists/' + list + '/prevRC/*.asc'
        LKrevcert = None
        for file in glob.glob(prevRevCert):
            if file:
                fr = open(file, 'r')
                LKrevcert = fr.read()
                fr.close()
        accept( list, userEmail, userpass, pubfile, secfile, LMpubfile, LSadminpubfile, LKpubfile,LKrevcert, LMConfig, debugflag )
    except KeyboardInterrupt:
        print ''
        print '%s' % sys.exc_type
        print 'shutting down'
        sys.exit()

def massKeyGen(line, list):
    try:
        lines = line.split()
        count = len(lines)
        if count >= 2:
            userEMail = lines[0]
            userName = lines[1]
            for i in range(2,count):
                name = lines[i]
                userName = userName + " " + name
            userName = userName.lstrip('(')
            userName = userName.rstrip(')')
        else:
            userEMail = lines[0]
            split = userEMail.split('@')
            userName = split[0]
        user = "%s (%s hosted at %s)"%(userName, list, SMTPDomain)
        return(user, userName, userEMail)
    except IndexError:
        sys.exit()

#******End Subscribe User Keys*********

def main(arvg=None):
    global LM_ID, LM_SIG_ID, LM_PASS,LM_SIG_PASS, LM_EMAIL, LS_ID, LS_EMAIL, LK_ID, SMTPDomain, MySMTPServer, MySMTPPort

    try:
        opts, args = getopt.getopt(sys.argv[1:], "ivphc:l:u:f",
                                   ["stdinpwd", "debug", "batch", "updatekeys", "createLMkeys","createListkey", "subscribeUser","installcheck","policyfilecheck", "help","version", 'pubfile=','randfile=', 'paramfile='])
    except getopt.GetoptError:
        print "Error: Unrecognized or incomplete option found"
        print ""
        usage()
    except KeyboardInterrupt:
        print '%s' % sys.exc_type
        print 'shutting down'
        sys.exit()

    list = ""
    cmd = ""
    createLMkeys = ""
    createListkey = ""
    subscribeUser = ""
    updatekeys = ""
    user = ""
    pubfile = ""
    randfile = ""
    paramfile = ""
    debugflag = 0
    batchflag = 0
    testflag = 0
    for o, v in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ( "-v", "--version"):
            version()
        elif o in ( "-i", "--installcheck"):
            checkinstall()
        elif o == "-c":
            cmd = v
        elif o == "-l":
            list = v
        elif o == "-u":
            user = v
        elif o == "--pubfile" :
            pubfile = v
        elif o == "--randfile":
            randfile = v
        elif o == "--paramfile":
            paramfile = v
        elif o == "--createLMkeys":
            createLMkeys = True
        elif o == "--createListkey":
            createListkey = True
        elif o == "--subscribeUser":
            subscribeUser = True
        elif o == "--updatekeys":
            updatekeys = True
        elif o == "--batch":
            batchflag = 1
        elif o == "--debug":
            debugflag = 1
        elif o == "--stdinpwd":
            testflag = 1
        elif o in ("-p", "--policyfilecheck"):
            policycheck()
            sys.exit()

    if (list == ""):
        print 'No option provided !'
        print ''
        usage()
    if batchflag == 1:
        #mass Key gen
        # Get the arguments from the command line, except the first one.
        args = sys.argv[1:]
        if len(args) == 5:
            pass
        else:
            print 'Wrong input arguments. Try again'
            usage()

    listSELSPath = LM_PATH + '/lists/' + list
    gnupg.options.homedir = listSELSPath

    if keyexp != "":
        yearstoexp = int(keyexp)
    else:
        yearstoexp = 1
    # not accounting for leap years
    secstoexp = yearstoexp * 365 * 24 * 60 * 60

    ########
    #Turning off batch and update keys
    batchflag = 0
    updatekeys = False
    ########
    if ((list != "")and (createLMkeys)):
        #Check to see if you have the right poilcy files
        policycheck()

        print 'Step 1: Creating meta data for list %s...'%(list)
        createMetaData(list, SMTPDomain, MySMTPServer, MySMTPPort, LS_EMAIL, testflag)

        LMConfig ={}
        # read list config file
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

        print 'Step 2: Generating El-Gamal parameters for %s...'%(list)


        # generate g, p, q
        genParams(list, debugflag)

        print 'Step 3: Generating List Moderator Key pair for %s...'%(list)

        # generate and install LM key pair
        genLMKeyPair(list, debugflag, secstoexp, testflag)

        print 'Step 4: Installing List Moderator key pair for %s...'%(list)
        # install LM enc key pair
        installLMEncKeyPair(list, False, debugflag)

        if debugflag:
            print LM_ID
            print LM_SIG_ID
        if LM_ID <> LM_SIG_ID:
            # install LM sig key pair
            installLMSigKeyPair(list, False, debugflag)
            # install LM key pair in user key Dir
            LMSigpubkey = installLMSigKeyPair(list, True, debugflag)
        else:
            LMSigpubkey = installLMEncKeyPair(list, True, debugflag)

        # send E-mail to LS
        print 'Step 6: Sending E-mail to List Server for %s...'%(list)

        print "Message to List Server is being signed by List Moderator..."

        try:
            print 'Enter password for List Moderator Signature key: '
            if testflag:
                pass1  = raw_input()
                print '!!!!'+pass1
            else:
                pass1 = getpass.getpass()

            LMConfig["LM_SIG_PASS"]=pass1
            LM_SIG_PASS=pass1
        except KeyboardInterrupt:
            print ''
            print '%s' % sys.exc_type
            print 'shutting down'
            sys.exit()

        sendLMEMailToLS(list, LMConfig, debugflag)
        print 'Wait for an email from List Server before creating %s keys'%(list)

    elif ((list != "")and updatekeys or createListkey or subscribeUser):
        if (createListkey == 1) or (updatekeys == 1):
            if updatekeys == 1 and batchflag == 0:
                print "File containing list of users' for this batch operation is missing.\n"
                usage()
            else:
                pass
            # read list config file & check to see if list directory and ascii files exists
            lmFilePath = listSELSPath + '/LM_pub.asc'
            lsadminFilePath = listSELSPath + '/LS_admin_verify.asc'
            if os.path.isdir(os.path.normpath(listSELSPath)):
                if os.path.isfile(os.path.normpath(lsadminFilePath)):
                    if (os.path.isfile(os.path.normpath(lmFilePath))):
                        print 'Follow the steps to generate list key'
                    else:
                        print 'List Moderator keys do not exist in %s directory. Create list again.'%(list)
                        print ''
                        usage()
                else:
                    print 'Error! List Server Administrator\'s  verification key is not present. Create metadata for %s again'%(list)
                    print ''
                    usage()
            else:
                print 'Create the list %s first. List %s directory does not exist'%(list, list)
                print ''
                usage()
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

            try:
                print 'Step1: Paste the List Server public key block for %s received via e-mail from List Server...'%(list)

                data=""
                while True:
                    line = sys.stdin.readline()
                    data = data + line
                    if line.startswith("-----END"):
                        break

                print 'Step2: Install List Server public key for list %s...'%(list)
                pubkeyFile = '%s/LS_pub.asc'%(listSELSPath)
                try:
                    fp = open( os.path.normpath(pubkeyFile), 'w')
                    fp.write(data)
                except IOError, (errno, strerror):
                    print "I/O error(%s): %s" % (errno, strerror)
                    sys.exit()

                else:
                    fp.close()
            except KeyboardInterrupt:
                print ''
                print '%s' % sys.exc_type
                print 'shutting down'
                sys.exit()

            installLSPubkey(list, debugflag)


            print 'Step3: Generating and installing list public key for list %s'%(list)

            ListKeyFile = listSELSPath + '/LK_pub.asc'
            regenerate = True
            if os.path.isfile(os.path.normpath(ListKeyFile)):
                print 'List key pair for list %s already exists. Do you want to overwrite? (yes/no)'%(list)
                input = raw_input()
                if( input != 'yes' ):
                    regenerate = False

            if regenerate:
                #Get LK_PASS
                print "Enter passphrase for List Key (LK) for list %s: "%(list)
                if testflag:
                    passlk = raw_input()
                else:
                    passlk = getpass.getpass()

                LK_PASS = passlk

                LKGen(list, debugflag, secstoexp, LK_PASS)
                installLKPubkey(list, debugflag)
            print 'Step4: Signing list public key for list %s...'%(list)
            try:
                print "Enter passphrase for List Moderator's signature key: "
                if testflag:
                    pass1 = raw_input()
                else:
                    pass1 = getpass.getpass()

                LMConfig["LM_SIG_PASS"] = pass1
                LM_SIG_PASS = pass1
                err = signLKPubkey(list, debugflag)
                while err.find("passphrase") <> -1:
                    print err
                    print 'Try again!'
                    pass1 = getpass.getpass("Enter passphrase for List Moderator's key: ")
                    LMConfig["LM_SIG_PASS"]=pass1
                    LM_SIG_PASS = pass1
                    err = signLKPubkey(list, debugflag)
            except KeyboardInterrupt:
                print ''
                print '%s' % sys.exc_type
                print 'shutting down'
                sys.exit()
            exportLKPubkey(list, debugflag)

            if regenerate == True:
                print 'Step6: Generating the revocation certificate for List Key'
                genRevoke(list, debugflag, LK_PASS)

                print 'Step7: Sending the list public key for list %s to List Server...'%(list)
            else:
                print 'Step6: Sending the list public key for list %s to List Server...'%(list)


            LKkeyid = getsubkeyid("LK")
            LKprimkeyid = getkeyid("LK")
            sendToLKPubToLS(list, LKkeyid, LKprimkeyid, LMConfig, debugflag)

            print 'Wait for an email from List Server before generating keys for subscribed users of list %s...'%(list)
            #Remove LK_secret.asc
            revseckey = listSELSPath + '/rev_secret.asc'
            if os.path.isfile(os.path.normpath(revseckey)):
                os.remove(os.path.normpath(revseckey))
            LK_ID = "LK (%s@%s) <%s@%s>"%(list,SMTPDomain, list,SMTPDomain)
            fingerprint = getFingerprint("=%s"%(LK_ID))
            if fingerprint != None:
                deleteSecretKey(fingerprint)
        else:
            pass

        if (subscribeUser == 1) or (updatekeys == 1):
            # read list config file & check to see if list directory and ascii files exists
            lmFilePath = listSELSPath + '/LM_pub.asc'
            if os.path.isdir(os.path.normpath(listSELSPath)):
                if (os.path.isfile(os.path.normpath(lmFilePath))):
                    print ''
                else:
                    print 'Keypair for %s managed by List Moderator does not exist in %s directory. Create list again.'%(list, list)
                    print ''
                    usage()
            else:
                print 'Create the list %s first. List %s directory does not exist'%(list, list)
                print ''
                usage()

            LMConfig ={}
            # read list config file
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

            # Check for first two steps
            LK_ID = "LK (%s@%s) <%s@%s>"%(list,SMTPDomain,list,SMTPDomain)
            fingerprintlk = getFingerprint("=%s" %(LK_ID))
            fingerprintlm = getFingerprint("=%s" %(LM_ID))
            lsadminFilePath = listSELSPath + '/LS_admin_verify.asc'
            lkFilePath = listSELSPath + '/LK_pub.asc'
            lmFilePath = listSELSPath + '/LM_pub.asc'
            lmSecFilePath = listSELSPath + '/LM_secret.asc'

            if os.path.isdir(os.path.normpath(listSELSPath)) and (fingerprintlm != None) and os.path.isfile(os.path.normpath(lsadminFilePath)):
                if os.path.isfile(os.path.normpath(lmFilePath))and os.path.isfile(os.path.normpath(lmSecFilePath)):
                    if (fingerprintlk != None) and os.path.isfile(os.path.normpath(lkFilePath)):
                        if batchflag == 0:
                            print 'Follow the steps to generate list subscriber key pair for list %s'%(list)
                        else:
                            print 'Start of the Batch Subscription Process for list %s. Follow the steps.'%(list)
                    else:
                        print 'List encryption Key does not exist. Create list key for %s'%(list)
                        print ''
                        usage()
                else:
                    print 'Key pair for %s does not exist. Create List Moderator keypair for %s'%(list,list)
                    print ''
                    usage()
            else:
                print 'Create metadata for the list %s again. Use option --createLMkeys' %(list)
                print ''
                usage()

            try:
                if batchflag == 0:
                    if len(user) == 0:
                        print "Enter List Subscriber's name: "
                        userName = raw_input()
                        print "Enter List Subscriber's email: "
                        userEmail = raw_input()
                        subuser = "%s (%s hosted at %s)"%(userName,list, SMTPDomain)
                        servuser = "%s(%s)<%s>"%(userName, list, userEmail)
                    else:
                        user = normUser(user)

                    print 'Step 1: Generate List %s Subscriber\'s key...'%(list)

                    if SubPass != "":
                        userpass = SubPass
                    else:
                        while (True):
                            print "Enter passphrase of private key for user %s: "%(userEmail)
                            if testflag:
                                pass1 = raw_input()
                            else:
                                pass1 = getpass.getpass()
                            print "Enter passphrase of private key again for user %s: "%(userEmail)
                            if testflag:
                                pass2 = raw_input()
                            else:
                                pass2 = getpass.getpass()

                            if pass1 == pass2 :
                                break
                            else:
                                print "Passphrase Mismatches!...Try again..."

                        userpass = pass1
                    print 'Step 2: Sign and Install List Subscriber\'s public key to ../lists/%s/user directory...'%(list)

                else:
                    args = sys.argv[1:]
                    if len(args) == 5:
                        # For Mass subscription create dummy user for checking passwords
                        subuser = "dummy (dummy hosted at dummy)"
                        servuser = "dummy (dummy) <dummy@dummy.dummy>"
                        # Set dummy user pass
                        userpass = "dummy"
                    else:
                        print" Wrong input arguments. Try again !"
                        usage()

                #Get LM_PASS
                print "Enter Passphrase for %s\'s private key. This key is managed by the List Moderator: "%(list)
                if testflag:
                    pass1 = raw_input()
                else:
                    pass1 = getpass.getpass()

                LMConfig["LM_PASS"]=pass1
                LM_PASS = pass1
                err = genUserKeyPair(list, subuser, servuser, userpass, debugflag, batchflag, secstoexp)
                while err:
                    pass1 = getpass.getpass("Enter Passphrase for %s\'s private key: "%(list))

                    LMConfig["LM_PASS"]=pass1
                    LM_PASS = pass1
                    err = genUserKeyPair(list, subuser, servuser, userpass, debugflag, batchflag, secstoexp)
                #Get LM_SIG_PASS
                print "Enter passphrase for List Moderator's signature key: "
                if testflag:
                    pass1 = raw_input()
                else:
                    pass1 = getpass.getpass()

                LMConfig["LM_SIG_PASS"]=pass1
                LM_SIG_PASS = pass1
                #Rolling back the subkey feature for PGP Desktop to work and adding removal of email address in Java code.
                #subuser's turn
                installUserPubkey(list, subuser, True, debugflag)
                err = signUserPubkey(list, subuser,debugflag)
                while err.find("passphrase") <> -1:
                    print err
                    print 'Try again!'
                    pass1 = getpass.getpass("Enter passphrase for List Moderator's signature key: ")
                    LMConfig["LM_SIG_PASS"]=pass1
                    LM_SIG_PASS = pass1
                    err = signUserPubkey(list, subuser, debugflag)

                if batchflag == 0:
                    exportUserPubkey(list, subuser, True, debugflag)

                    print '\nStep 3: Sending E-mail to %s of %s...'%(subuser, list)
                    # send E-mail to user
                    sendEMailToUser(list, subuser, userEmail, userpass, LMConfig, debugflag)
                    deleteUserkey(list, subuser)
                    # servuser's turn
                    installUserPubkey(list, servuser, False, debugflag)
                    err = signUserPubkey(list, servuser, debugflag)
                    while err.find("passphrase") <> -1:
                        print err
                        print 'Try again!'
                        pass1 = getpass.getpass("Enter passphrase for List Moderator's signature key: ")
                        LMConfig["LM_SIG_PASS"]=pass1
                        LM_SIG_PASS = pass1
                        err = signUserPubkey(list, servuser,debugflag)

                    exportUserPubkey(list, servuser, False, debugflag)
                    print 'Step 4: Sending E-mail to LS for %s of %s...'%(servuser, list)
                    # send E-mail to LS
                    sendEMailToLS(list, servuser, userEmail, LMConfig, debugflag)
                    deleteUserkey(list, servuser)
                #Delete ascii files
                pubkey = '%s/%s_subpub.asc'%(listSELSPath, sha.new(subuser).hexdigest())
                seckey = '%s/%s_subsecret.asc'%(listSELSPath, sha.new(subuser).hexdigest())
                servpubkey = '%s/%s_servpub.asc'%(listSELSPath, sha.new(servuser).hexdigest())
                servseckey = '%s/%s_servsecret.asc'%(listSELSPath, sha.new(servuser).hexdigest())
                if os.path.isfile(os.path.normpath(pubkey)):
                    os.remove(os.path.normpath(pubkey))

                if os.path.isfile(os.path.normpath(seckey)):
                    os.remove(os.path.normpath(seckey))

                if os.path.isfile(os.path.normpath(servpubkey)):
                    os.remove(os.path.normpath(servpubkey))

                if os.path.isfile(os.path.normpath(servseckey)):
                    os.remove(os.path.normpath(servseckey))
                if batchflag == 1:
                    #mass Key gen
                    # Get the arguments from the command line, except the first one.
                    args = sys.argv[1:]
                    if len(args) == 5:
                        # Open the file for read only.
                        infile = file(args[4], 'r')
                        # Create an outfile for passwords only if SubPass = "" (from SELSLMConfig.py)
                        if (SubPass == ""):
                            fname = listSELSPath + "/SELS-%s.txt"%(list)
                            try:
                                os.remove(fname)
                            except:
                                None
                            outfile = file(fname, 'a')
                        else:
                            pass
                        counter = 1
                        # Iterate over the lines in the file.
                        for line in infile:
                            (subuser, userName, userEmail) = massKeyGen(line, list)
                            servuser = "%s(%s)<%s>"%(userName, list, userEmail)

                            if (SubPass == "") :
                                userpass = genPass()
                                fstring = userEmail + "\t" + userpass + "\n"
                                outfile.write(fstring)
                            else:
                                userpass = SubPass
                            print "Subscribing user #%s \"%s\" to %s ..."%(counter, userEmail, list)
                            genUserKeyPair(list, subuser,servuser, userpass, debugflag, batchflag, secstoexp)
                            #Rolling back the subkey feature for PGP Desktop to work.
                            installUserPubkey(list, subuser, True, debugflag)
                            signUserPubkey(list, subuser, debugflag)
                            exportUserPubkey(list, subuser, True, debugflag)
                            sendEMailToUser(list, subuser, userEmail, userpass, LMConfig, debugflag)
                            deleteUserkey(list, subuser)
                            installUserPubkey(list, servuser, False, debugflag)
                            signUserPubkey(list, servuser, debugflag)
                            exportUserPubkey(list, servuser, False, debugflag)
                            deleteUserkey(list, servuser)
                            sendEMailToLS(list, servuser,userEmail,  LMConfig, debugflag)
                            pubkey = '%s/%s_subpub.asc'%(listSELSPath, sha.new(subuser).hexdigest())
                            seckey = '%s/%s_subsecret.asc'%(listSELSPath, sha.new(subuser).hexdigest())
                            servpubkey = '%s/%s_servpub.asc'%(listSELSPath, sha.new(servuser).hexdigest())
                            servseckey = '%s/%s_servsecret.asc'%(listSELSPath, sha.new(servuser).hexdigest())
                            if os.path.isfile(os.path.normpath(pubkey)):
                                os.remove(os.path.normpath(pubkey))

                            if os.path.isfile(os.path.normpath(seckey)):
                                os.remove(os.path.normpath(seckey))

                            if os.path.isfile(os.path.normpath(servpubkey)):
                                os.remove(os.path.normpath(servpubkey))

                            if os.path.isfile(os.path.normpath(servseckey)):
                                os.remove(os.path.normpath(servseckey))
                            counter += 1
                            print "Done"
                        if (SubPass == ""):
                            outfile.close()
                        infile.close()
                        dummyuser = "dummy"
                        deleteUserkey(list, dummyuser)
                        print "End of Batch Subscription Process."
                    else:
                        print 'Wrong input arguments. Try again'
                        usage()

                sigkey = listSELSPath + '/LM_sig_secret.asc'
                if os.path.isfile(os.path.normpath(sigkey)):
                    os.remove(os.path.normpath(sigkey))
                #Can't delete LM secret key. This is needed during User key pair generation
            except KeyboardInterrupt:
                print ''
                print '%s' % sys.exc_type
                print 'shutting down'
        else:
            pass
    else:
        print 'Wrong input arguments. Try again'
        print ''
        usage()

    return 0

if __name__ == "__main__":
    sys.exit(main())
