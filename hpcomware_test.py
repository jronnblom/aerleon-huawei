import pytest
from unittest import mock

import hpcomware

from aerleon.lib import naming
from aerleon.lib import policy


GOOD_HEADER = """
header {
  comment:: "foooad bar"
  target:: hpcomware foo advanced auto
}
"""
MULTILINE_COMMENT = """
header {
  comment:: "foo"
  comment:: "bar"
  target:: hpcomware foo auto
}
"""

GOOD_TERM = """
term foo {
  source-address:: FOO
  destination-address:: GOOGLE_DNS
  destination-port:: DNS
  protocol:: tcp
  action:: accept
}
"""

EXP_INFO = 2


def test_hpcomware():
    expect = """acl advanced name foo match-order auto
description foooad bar
step 1
acl permit tcp source 192.168.1.1 0 source-port range 0 65535 destination 8.8.4.4 0 destination-port eq 53
acl permit tcp source 192.168.1.1 0 source-port range 0 65535 destination 8.8.8.8 0 destination-port eq 53
acl permit tcp source 192.168.1.2 0 source-port range 0 65535 destination 8.8.4.4 0 destination-port eq 53
acl permit tcp source 192.168.1.2 0 source-port range 0 65535 destination 8.8.8.8 0 destination-port eq 53"""
    names = naming.Naming("./defs")
    acl = hpcomware.HPComware(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM, names), EXP_INFO
    )
    assert str(acl) == expect

