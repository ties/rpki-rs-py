from pathlib import Path

import rpki_rs

def test_manifest_parsing():
    data = Path(__file__).parent / "data/F43VHX5As0tDn4_fTQUUEcU0cuo.mft"
    with data.open("rb") as f:
        mft = rpki_rs.RpkiManifest.from_content(f.read())
        import ipdb; ipdb.set_trace()
