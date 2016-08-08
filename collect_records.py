#!/usr/bin/env python
"""
Collects audit records from the local filesystem, and ships them up to the centralized system.
"""


import os
import sys
import glob
from audit2json import Audit2JSON

def main():
    """
    Executable mainline function
    """
    if not os.geteuid() == 0:
        print "This script must run as root, engaging sudo-powers..."
        os.execv('/usr/bin/sudo', ['python'] + sys.argv)
        sys.exit('Running sudo failed somehow')

    auditdir    = '/var/log/audit'
    auditfiles  = glob.glob(auditdir+'/audit.log.*')

    index       = 0
    max_entries = 10

    for audit in auditfiles:
        stream = Audit2JSON(audit)
        for entry in stream.get_entry():
            index += 1
            if index >= max_entries:
                sys.exit('Max Entries (%d) reached, consider increasing the maximum' % (max_entries))
            print entry

if __name__ == '__main__':
    main()
