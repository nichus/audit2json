import sys
import auparse
import audit

def none_to_null(word):
    'used so output matches C version'
    if word is None:
        return '(null)'
    else:
        return word

def parse_file(auditfile):
    """
        Borrowed heavily (read stolen outright) from
        https://svn.fedorahosted.org/svn/audit/branches/1.8/auparse/test/auparse_test.py
    """
    auditstream = auparse.AuParser(auparse.AUSOURCE_FILE, auditfile)
    event_cnt = 1

    auditstream.reset()
    while True:
        if not auditstream.first_record():
            print "Error getting first record"
            sys.exit(1)

        print "event %d has %d records" % (event_cnt, auditstream.get_num_records())

        record_cnt = 1
        while True:
            print "    record %d of type %d(%s) has %d fields" % \
                  (record_cnt,
                   auditstream.get_type(), audit.audit_msg_type_to_name(auditstream.get_type()),
                   auditstream.get_num_fields())
            print "    line=%d file=%s" % (auditstream.get_line_number(), auditstream.get_filename())
            event = auditstream.get_timestamp()
            if event is None:
                print "Error getting timestamp - aborting"
                sys.exit(1)

            print "    event time: %d.%d:%d, host=%s" % (event.sec, event.milli,
                    event.serial, none_to_null(event.host))
            auditstream.first_field()
            while True:
                print "        %s=%s (%s)" % (  auditstream.get_field_name(),
                                                auditstream.get_field_str(),
                                                auditstream.interpret_field())
                if not auditstream.next_field():
                    break
            print
            record_cnt += 1
            if not auditstream.next_record():
                break
        event_cnt += 1
        if not auditstream.parse_next_event():
            break
