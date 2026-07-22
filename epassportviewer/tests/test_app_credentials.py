import pytest

from epassportviewer.app import _credential_state


@pytest.mark.parametrize(
    ("doc_number", "dob", "expiry", "can", "ready", "missing"),
    [
        ("", "", "", "", False, {"doc_number", "dob", "expiry"}),
        ("EP123456", "", "", "", False, {"dob", "expiry"}),
        ("EP123456", "900101", "300101", "", True, set()),
        ("", "", "", "123456", True, set()),
    ],
)
def test_credential_state_requires_full_mrz_or_can(doc_number, dob, expiry, can, ready, missing):
    assert _credential_state(doc_number, dob, expiry, can) == (ready, missing)
