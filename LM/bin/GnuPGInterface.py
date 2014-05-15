import os
import sys

__author__   = "Frank J. Tobin, ftobin@neverending.org"
__version__  = "0.3.2"
__revision__ = "$Id: GnuPGInterface.py,v 1.1.1.1 2007/06/13 19:10:59 mpant Exp $"

# "standard" filehandles attached to processes
_stds = [ 'stdin', 'stdout', 'stderr' ]

# correlation between handle names and the arguments we'll pass
_fd_options = { 'passphrase': '--passphrase-fd',
                'logger':     '--logger-fd',
                'status':     '--status-fd',
                'command':    '--command-fd' }

class GnuPG:
    """Class instances represent GnuPG.

    Instance attributes of a GnuPG object are:

    * call -- string to call GnuPG with.  Defaults to "gpg"

    * passphrase -- Since it is a common operation
      to pass in a passphrase to GnuPG,
      and working with the passphrase filehandle mechanism directly
      can be mundane, if set, the passphrase attribute
      works in a special manner.  If the passphrase attribute is set,
      and no passphrase file object is sent in to run(),
      then GnuPG instnace will take care of sending the passphrase to
      GnuPG, the executable instead of having the user sent it in manually.

    * options -- Object of type GnuPGInterface.Options.
      Attribute-setting in options determines
      the command-line options used when calling GnuPG.
    """

    def __init__(self):
        self.call = 'gpg'
        self.passphrase = None
        self.options = Options()

    def run(self, gnupg_commands, args=None):
        if args == None:
            args = []

        passphrase_fd_0 = []
        if self.passphrase != None:
            passphrase_fd_0 = ["--passphrase-fd", "0"]


        command = [ self.call ] + passphrase_fd_0 + self.options.get_args() \
          + gnupg_commands + args

        cmd_str = ""

        for item in command:
            cmd_str = cmd_str + item + " "

        cmd_str = os.path.normpath(cmd_str)
        stdin, stdout, stderr = os.popen3( cmd_str )

        if (self.passphrase != None ):
            stdin.write(self.passphrase)
            stdin.close()

        outmsg = stdout.read()
        errmsg = stderr.read()

        stdout.close()
        stderr.close()

        return outmsg, errmsg

#        os.execvp( command[0], command )

class Pipe:
    """simple struct holding stuff about pipes we use"""
    def __init__(self, parent, child, direct):
        self.parent = parent
        self.child = child
        self.direct = direct


class Options:
    """Objects of this class encompass options passed to GnuPG.
    This class is responsible for determining command-line arguments
    which are based on options.  It can be said that a GnuPG
    object has-a Options object in its options attribute.

    Attributes which correlate directly to GnuPG options:

    Each option here defaults to false or None, and is described in
    GnuPG documentation.

    Booleans (set these attributes to booleans)

      * armor
      * no_greeting
      * no_verbose
      * quiet
      * batch
      * always_trust
      * rfc1991
      * openpgp
      * force_v3_sigs
      * no_options
      * textmode

    Strings (set these attributes to strings)

      * homedir
      * default_key
      * comment
      * compress_algo
      * options

    Lists (set these attributes to lists)

      * recipients  (***NOTE*** plural of 'recipient')
      * encrypt_to

    Meta options

    Meta options are options provided by this module that do
    not correlate directly to any GnuPG option by name,
    but are rather bundle of options used to accomplish
    a specific goal, such as obtaining compatibility with PGP 5.
    The actual arguments each of these reflects may change with time.  Each
    defaults to false unless otherwise specified.

    meta_pgp_5_compatible -- If true, arguments are generated to try
    to be compatible with PGP 5.x.

    meta_pgp_2_compatible -- If true, arguments are generated to try
    to be compatible with PGP 2.x.

    meta_interactive -- If false, arguments are generated to try to
    help the using program use GnuPG in a non-interactive
    environment, such as CGI scripts.  Default is true.

    extra_args -- Extra option arguments may be passed in
    via the attribute extra_args, a list.

    >>> import GnuPGInterface
    >>>
    >>> gnupg = GnuPGInterface.GnuPG()
    >>> gnupg.options.armor = 1
    >>> gnupg.options.recipients = ['Alice', 'Bob']
    >>> gnupg.options.extra_args = ['--no-secmem-warning']
    >>>
    >>> # no need for users to call this normally; just for show here
    >>> gnupg.options.get_args()
    ['--armor', '--recipient', 'Alice', '--recipient', 'Bob', '--no-secmem-warning']
    """

    def __init__(self):
        # booleans
        self.armor = 0
        self.no_greeting = 0
        self.verbose = 0
        self.no_verbose = 0
        self.quiet = 0
        self.batch = 0
        self.always_trust = 0
        self.rfc1991 = 0
        self.openpgp = 0
        self.force_v3_sigs = 0
        self.no_options = 0
        self.textmode = 0

        # meta-option booleans
        self.meta_pgp_5_compatible = 0
        self.meta_pgp_2_compatible = 0
        self.meta_interactive = 1

        # strings
        self.homedir = None
        self.default_key = None
        self.comment = None
        self.compress_algo = None
        self.options = None

        # lists
        self.encrypt_to = []
        self.recipients = []

        # miscellaneous arguments
        self.extra_args = []

    def get_args( self ):
        """Generate a list of GnuPG arguments based upon attributes."""

        return self.get_meta_args() + self.get_standard_args() + self.extra_args

    def get_standard_args( self ):
        """Generate a list of standard, non-meta or extra arguments"""
        args = []
        if self.homedir != None: args.extend( [ '--homedir', self.homedir ] )
        if self.options != None: args.extend( [ '--options', self.options ] )
        if self.comment != None: args.extend( [ '--comment', self.comment ] )
        if self.compress_algo != None: args.extend( [ '--compress-algo', self.compress_algo ] )
        if self.default_key != None: args.extend( [ '--default-key', self.default_key ] )

        if self.no_options: args.append( '--no-options' )
        if self.armor: args.append( '--armor' )
        if self.textmode: args.append( '--textmode' )
        if self.no_greeting: args.append( '--no-greeting' )
        if self.verbose: args.append( '--verbose' )
        if self.no_verbose: args.append( '--no-verbose' )
        if self.quiet: args.append( '--quiet' )
        if self.batch: args.append( '--batch' )
        if self.always_trust: args.append( '--always-trust' )
        if self.force_v3_sigs: args.append( '--force-v3-sigs' )
        if self.rfc1991: args.append( '--rfc1991' )
        if self.openpgp: args.append( '--openpgp' )

        for r in self.recipients: args.extend( [ '--recipient',  r ] )
        for r in self.encrypt_to: args.extend( [ '--encrypt-to', r ] )

        return args

    def get_meta_args( self ):
        """Get a list of generated meta-arguments"""
        args = []

        if self.meta_pgp_5_compatible: args.extend( [ '--compress-algo', '1',
                                                      '--force-v3-sigs'
                                                      ] )
        if self.meta_pgp_2_compatible: args.append( '--rfc1991' )
        if not self.meta_interactive: args.extend( [ '--batch', '--no-tty' ] )

        return args


class Process:
    """Objects of this class encompass properties of a GnuPG
    process spawned by GnuPG.run().

    # gnupg is a GnuPG object
    process = gnupg.run( [ '--decrypt' ], stdout = 1 )
    out = process.handles['stdout'].read()
    ...
    os.waitpid( process.pid, 0 )

    Data Attributes

    handles -- This is a map of filehandle-names to
    the file handles, if any, that were requested via run() and hence
    are connected to the running GnuPG process.  Valid names
    of this map are only those handles that were requested.

    pid -- The PID of the spawned GnuPG process.
    Useful to know, since once should call
    os.waitpid() to clean up the process, especially
    if multiple calls are made to run().
    """

    def __init__(self):
        self._pipes  = {}
        self.handles = {}
        self.pid     = None
        self._waited = None
        self.gpgThread = None

    def wait(self):
        """Wait on the process to exit, allowing for child cleanup.
        Will raise an IOError if the process exits non-zero."""
        self.gpgThread.join()

def _run_doctests():
    import doctest, GnuPGInterface
    return doctest.testmod(GnuPGInterface)

# deprecated
GnuPGInterface = GnuPG

if __name__ == '__main__':
    _run_doctests()
