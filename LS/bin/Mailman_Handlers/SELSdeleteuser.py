#!/usr/bin/python
# Created by: SELS Team
#
# Description: Script to delete User Keys from ../mailman/lists/<listname>/SELS when invoked from OldStyleMemberships.py
#
# License: This code is a part of SELS distribution under NCSA/UIUC Open Source License (refer NCSA-license.txt)
############################################################################################################################

import os
from Mailman import Errors
from Mailman.Logging.Syslog import syslog
from SELSpath import *
from mailmanlogs import *

def Removekeys(listname, addr):
    selslog = MAILMAN_LOG_PATH + "/SELS.log"
    cmd = "python %s/bin/SELSProcess.py -l %s -u %s -d >> %s 2>&1"%\
           (SELSPATH,listname,addr, selslog)
    os.system(cmd)
    syslog("error"," Subscriber %s SELS keys removed from  list %s"% (addr, listname))
