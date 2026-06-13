"""Unit tests for the offline BAC brute-force attack.

These tests run entirely offline (no PC/SC, no card): ``BruteForce`` is
created with ``activateReader=False`` so the ISO 7816 transport is never
touched. They pin the offline MAC path against the ICAO Doc 9303 Part 11
worked example and exercise the offline brute-force search end to end.
"""

from pypassport.attacks.brute_force import BruteForce
from pypassport.doc9303.mrz import MRZ
from pypassport.iso9797 import mac, pad


# ICAO Doc 9303 Part 11, Appendix D worked example.
ICAO_MRZ_INFORMATION = "L898902C<369080619406236"
ICAO_KSEED = "239AB9CB282DAF66231DC5A4DF6BFBAE"
ICAO_KENC = "AB94FDECF2674FDFB9B391F85D7F76F2"
ICAO_KMAC = "7962D9ECE03D1ACD4C76089DCE131543"
ICAO_EIFD = "72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2"
ICAO_MIFD = "5F1448EEA8AD90A7"

# The document number / DOB / expiry that make up the worked example MRZ.
ICAO_DOC = "L898902C"
ICAO_DOB = "690806"
ICAO_EXP = "940623"


def test_offline_key_derivation_matches_icao_vector():
    """genKseed + keyDerivation reproduce the published ICAO keys."""
    bf = BruteForce(None, activateReader=False)
    kseed = bf._genKseed(ICAO_MRZ_INFORMATION)
    assert kseed.hex().upper() == ICAO_KSEED
    assert bf._keyDerivation(kseed, BruteForce.KENC).hex().upper() == ICAO_KENC
    assert bf._keyDerivation(kseed, BruteForce.KMAC).hex().upper() == ICAO_KMAC


def test_offline_mac_matches_icao_vector():
    """The ISO 9797-1 retail MAC over E.IFD equals the published M.IFD.

    This is the exact comparison ``exploitOffline`` performs for every
    candidate MRZ, so a green here means the offline match path is sound.
    """
    kmac = bytes.fromhex(ICAO_KMAC)
    calculated = mac(kmac, pad(bytes.fromhex(ICAO_EIFD)))
    assert calculated == bytes.fromhex(ICAO_MIFD)


def _single_candidate_bruteforce(doc, dob, exp):
    bf = BruteForce(None, activateReader=False)
    bf.setID(low=doc, high=doc)
    bf.setDOB(low=dob, high=dob)
    bf.setExpDate(low=exp, high=exp)
    return bf


def test_exploit_offline_finds_matching_mrz():
    """A pair forged with the victim's MRZ is recovered by the search."""
    mrz_str = MRZ((ICAO_DOC, ICAO_DOB, ICAO_EXP)).mrz
    bf = _single_candidate_bruteforce(ICAO_DOC, ICAO_DOB, ICAO_EXP)
    pair = bf.initOffline(mrz_str)

    found = bf.exploitOffline(pair)
    assert found
    assert found.startswith(ICAO_DOC)


def test_exploit_offline_rejects_wrong_range():
    """A search whose range excludes the victim MRZ finds nothing."""
    mrz_str = MRZ((ICAO_DOC, ICAO_DOB, ICAO_EXP)).mrz
    # Forge the pair with the real document number...
    pair = _single_candidate_bruteforce(ICAO_DOC, ICAO_DOB, ICAO_EXP).initOffline(mrz_str)
    # ...but search a disjoint document-number range.
    wrong = _single_candidate_bruteforce("A0000000", ICAO_DOB, ICAO_EXP)
    assert wrong.exploitOffline(pair) is False
