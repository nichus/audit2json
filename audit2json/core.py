"""Define the Audit2JSON object for parsing audit log files
"""

import sys
import auparse
import audit
from datetime import datetime

class Audit2JSON(object): #pylint: disable=too-few-public-methods
    """JSONify audit log entries"""
    def __init__(self, filename):
        """Opens the specified audit file and prepares it for processing"""
        self.auditstream = auparse.AuParser(auparse.AUSOURCE_FILE, filename)

        self.auditstream.reset()

        if not self.auditstream.first_record():
            print "Error getting first record"
            sys.exit(1)

    def get_entry(self):
        """Return the next record from the currently processed audit file"""
        # remember to 'yield json.dumps(entry)' after the object has been built
        # this will return the object to the caller

        # Event Loop
        while True:
            event = {}
            event['count']      = self.auditstream.get_num_records()
            event['records']    = []
            # Record Loop
            while True:
                record = {}
                headers = {}
                timestamp   = self.auditstream.get_timestamp()
                if timestamp is None:
                    print "Error getting event timestamp, aborting"
                    sys.exit(1)
                headers['fieldcount']   = self.auditstream.get_num_fields()
                headers['typenum']      = self.auditstream.get_type()
                headers['type']         = audit.audit_msg_type_to_name(headers['typenum'])
                headers['location']     = '%s:%d' % ( self.auditstream.get_filename(), self.auditstream.get_line_number() )
                headers['unixtime']     = float("%d.%d" % (timestamp.sec,timestamp.milli))
                headers['isotime']      = datetime.fromtimestamp(headers['unixtime']).isoformat()
                headers['serial']       = timestamp.serial
                headers['host']         = timestamp.host

                record['headers']       = headers

                fields                  = {}
                # Field Loop
                self.auditstream.first_field()
                while True:
                    fields[self.auditstream.get_field_name()] = {
                              'raw':    self.auditstream.get_field_str(),
                            'value':    self.auditstream.interpret_field()
                            }
                    if self.auditstream.get_field_name() == "proctitle":
                        fields[self.auditstream.get_field_name()]['value'] = self.auditstream.get_field_str().decode("hex").split('\x00')[0]
                    if not self.auditstream.next_field():
                        break
                record['fields']    = fields
                event['records'].append(record)
                if not self.auditstream.next_record():
                    break
            yield event
            if not self.auditstream.parse_next_event():
                break

def none_to_null(word):
    'used so output matches C version'
    if word is None:
        return '(null)'
    else:
        return word
