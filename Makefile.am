#********************************#
#Makefile.am
#Written by: Meenal Pant
#Date:Aug-14-2007
#********************************#
AUTOMAKE_OPTIONS = foreign dist-zip
SUBDIRS = gpglib
EXTRA_DIST = LM LS common ChangeLog README SELSTeam INSTALL NCSA-license.txt
dist-hook:
	rm -rf `find $(distdir)/LM/bin -name unittest_config.py`
	rm -rf `find $(distdir)/LM/bin -name unittest_helper.py`
	rm -rf `find $(distdir)/LM/bin -name unittest_initLM.py`
	rm -rf `find $(distdir)/LM/bin -name unittest_LM.py`
	rm -rf `find $(distdir)/LM/bin -name unittestREADME`
	rm -rf `find $(distdir)/LM/ -name inttest`
	rm -rf `find $(distdir)/LM -name .svn`
	rm -rf `find $(distdir)/LM/bin -name .svn`
	rm -rf `find $(distdir)/LM/lists -name .svn`
	rm -rf `find $(distdir)/LS -name .svn`
	rm -rf `find $(distdir)/LS/bin -name .svn`
	rm -rf `find $(distdir)/LS/ -name tests`
	rm -rf `find $(distdir)/common -name .svn`
	rm -rf `find $(distdir)/common/lib -name .svn`
	rm -rf `find $(distdir)/common/src -name .svn`
	rm -rf `find $(distdir)/common/lib/1.4 -name .svn`
	rm -rf `find $(distdir)/common/lib/1.5 -name .svn`
	rm -rf `find $(distdir)/common/lib/1.6 -name .svn`
	rm -rf `find $(distdir)/common/src/java -name .svn`


