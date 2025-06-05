from pathlib import Path

import rpki_rs

def test_manifest_parsing():
    data = Path(__file__).parent / "data/F43VHX5As0tDn4_fTQUUEcU0cuo.mft"
    with data.open("rb") as f:
        mft = rpki_rs.RpkiManifest.from_content(f.read())
        assert mft.file_list[0].file == "F43VHX5As0tDn4_fTQUUEcU0cuo.crl"
        assert mft.file_list[0].hash.hex() == "57b7bc28438838b4b469b71905414d6a75aa861ad687fc66a44d5268d1f1f091"
