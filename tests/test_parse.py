import datetime
from pathlib import Path

import rpki_rs

def test_parse__manifest():
    data = Path(__file__).parent / "data/F43VHX5As0tDn4_fTQUUEcU0cuo.mft"
    with data.open("rb") as f:
        mft = rpki_rs.parse(f.name, f.read())
        # Other field parsing already covered in test_manifest_parsing.py - this covers the generic parse function.
        assert mft.signing_time == datetime.datetime(2025, 6, 4, 23, 0, 27, tzinfo=datetime.timezone.utc)