import datetime
from pathlib import Path

import rpki_rs

def test_signing_time_present():
    data = Path(__file__).parent / "data/sample-roa-ipv4-maxlen.roa"
    with data.open("rb") as f:
        signing_time = rpki_rs.cms_signing_time(f.read())
        assert signing_time == 1735695879

def test_signing_time_missing():
    data = Path(__file__).parent / "data/badCMSSigInfoAttrsSigTime0Val.roa"
    with data.open("rb") as f:
        signing_time = rpki_rs.cms_signing_time(f.read())
        assert signing_time == None