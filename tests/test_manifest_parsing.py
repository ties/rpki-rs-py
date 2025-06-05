import datetime
from pathlib import Path

import rpki_rs

def test_manifest_parsing():
    data = Path(__file__).parent / "data/F43VHX5As0tDn4_fTQUUEcU0cuo.mft"
    with data.open("rb") as f:
        mft = rpki_rs.Manifest.from_content(f.read())
        assert mft is not None

        assert mft.aki.hex() == "17:8D:D5:1D:7E:40:B3:4B:43:9F:8F:DF:4D:05:14:11:C5:34:72:EA".replace(":", "").lower()
        assert mft.ski.hex() == "0B:E6:AF:F6:EA:FE:D9:15:7B:40:63:BD:4F:F7:26:88:A3:FA:E3:06".replace(":", "").lower()

        assert mft.signing_time == datetime.datetime(2025, 6, 4, 23, 0, 27, tzinfo=datetime.timezone.utc)
        assert mft.this_update == datetime.datetime(2025, 6, 4, 23, 0, 27, tzinfo=datetime.timezone.utc)
        assert mft.next_update == datetime.datetime(2025, 6, 5, 23, 0, 27, tzinfo=datetime.timezone.utc)

        assert mft.manifest_number == int("033C", 16)

        assert mft.aia == "rsync://rpki.ripe.net/repository/DEFAULT/F43VHX5As0tDn4_fTQUUEcU0cuo.cer"
        assert mft.sia == "rsync://rpki.ripe.net/repository/DEFAULT/1b/876fc7-6552-4d41-89ae-87aa9d8772f3/1/F43VHX5As0tDn4_fTQUUEcU0cuo.mft"

        # files
        assert mft.file_list[0].file == "F43VHX5As0tDn4_fTQUUEcU0cuo.crl"
        assert mft.file_list[0].hash.hex() == "57b7bc28438838b4b469b71905414d6a75aa861ad687fc66a44d5268d1f1f091"

        assert len(mft) == 2
        assert mft[1] == mft.file_list[1]
