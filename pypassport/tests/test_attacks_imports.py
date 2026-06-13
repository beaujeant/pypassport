"""All attack modules import and expose their public classes.

Acceptance guard: every module in pypassport.attacks must import cleanly
against the current API, and the package must re-export the public classes.
"""

import pypassport.attacks as attacks


def test_public_classes_are_exported():
    expected = {
        "BruteForce",
        "BruteForceException",
        "MacTraceability",
        "MacTraceabilityException",
        "ErrorFingerprinting",
        "ErrorFingerprintingException",
        "SignEverything",
        "SignEverythingException",
        "AATraceability",
        "AATraceabilityException",
    }
    assert expected.issubset(set(attacks.__all__))
    for name in expected:
        assert hasattr(attacks, name), f"{name} not exported from pypassport.attacks"
