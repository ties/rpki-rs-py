import base64
import datetime
from pathlib import Path

import rpki_rs


def test_parse_aspa():
    data = Path(__file__).parent / "data/o1qu9kAQGyrDid3Spblf5v3dgGE.asa"
    with data.open("rb") as f:
        aspa = rpki_rs.parse(f.name, f.read())

        assert aspa.serial_number == 140634067609421699249212042701971768582440
        # rpki-client prints timezone by accident
        # Signing time:             Wed 01 Apr 2026 13:51:25 +0100
        assert aspa.signing_time == datetime.datetime(
            2026, 4, 1, 13, 51, 25, tzinfo=datetime.timezone.utc
        )
        # ASPA not before:          Wed 01 Apr 2026 13:51:25 +0100
        assert aspa.not_before == datetime.datetime(
            2026, 4, 1, 13, 51, 25, tzinfo=datetime.timezone.utc
        )
        # ASPA not after:           Thu 01 Jul 2027 00:00:00 +0100
        assert aspa.not_after == datetime.datetime(
            2027, 7, 1, 0, 0, 0, tzinfo=datetime.timezone.utc
        )

        # Customer ASID:            212966
        assert aspa.customer_as == 212966
        # Providers:                AS: 47447
        #                           AS: 200461
        assert aspa.providers == [47447, 200461]


def test_parse__crl():
    data = Path(__file__).parent / "data/7DNNDzoYvgAht7joQih2Qayxcxo.crl"
    with data.open("rb") as f:
        crl = rpki_rs.parse(f.name, f.read())

        assert crl.crl_number == 2976
        # thisUpdate utcTime Time UTCTime 2026-05-03 14:00:49 UTC
        assert crl.this_update == datetime.datetime(
            2026, 5, 3, 14, 00, 49, tzinfo=datetime.timezone.utc
        )
        # nextUpdate utcTime Time UTCTime 2026-05-04 14:00:49 UTC
        assert crl.next_update == datetime.datetime(
            2026, 5, 4, 14, 0, 49, tzinfo=datetime.timezone.utc
        )

        assert len(crl.revoked_certificates) == 585
        assert crl.revoked_certificates[-1] == rpki_rs.RevokedCertificate(
            140850596639850458217639837785840367100648,
            datetime.datetime(2026, 5, 3, 14, 0, 49, tzinfo=datetime.timezone.utc),
        )


def test_parse_cert():
    data = Path(__file__).parent / "data/_0cFo2PcHY0OpRybmh7L04B70FQ.cer"
    with data.open("rb") as f:
        cert = rpki_rs.parse(f.name, f.read())

        assert cert.serial_number == 140017544980660388417784593703853101077576
        # notBefore utcTime Time UTCTime 2026-01-01 12:17:56 UTCOffset: 103
        assert cert.not_before == datetime.datetime(
            2026, 1, 1, 12, 17, 56, tzinfo=datetime.timezone.utc
        )
        # notAfter utcTime Time UTCTime 2027-07-01 00:00:00 UTC
        assert cert.not_after == datetime.datetime(
            2027, 7, 1, 0, 0, 0, tzinfo=datetime.timezone.utc
        )


def test_parse__manifest():
    data = Path(__file__).parent / "data/F43VHX5As0tDn4_fTQUUEcU0cuo.mft"
    with data.open("rb") as f:
        mft = rpki_rs.parse(f.name, f.read())
        # Other field parsing already covered in test_manifest_parsing.py - this covers the generic parse function.
        assert mft.signing_time == datetime.datetime(
            2025, 6, 4, 23, 0, 27, tzinfo=datetime.timezone.utc
        )
        assert [(entry.file, entry.hash) for entry in mft.file_list] == [
            (
                "F43VHX5As0tDn4_fTQUUEcU0cuo.crl",
                base64.b64decode("V7e8KEOIOLS0abcZBUFNanWqhhrWh/xmpE1SaNHx8JE="),
            ),
            (
                "sY0r0y4AruQYBO-qa1jtodSMRJI.roa",
                base64.b64decode("fgiZ0pPukyfp5f/cG9pJMs5XjY+lIWQ3prMocyZ72Vo="),
            ),
        ]
