"""
"""
from .context import Audit2JSON

def test_get_entry():
    stream  = Audit2JSON("tests/audit.log")
    entry   = next(stream.get_entry(),None)
    assert entry != None
    print entry

