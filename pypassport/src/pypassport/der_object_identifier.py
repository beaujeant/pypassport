"""DER Object Identifier (OID) lookup tables for passport algorithm identification.

OID maps an OID dotted-string to a human-readable algorithm name.
OIDrevert provides the reverse mapping.
passive_authentication.py uses a dedicated _HASH_ALGORITHMS dispatch table
(keyed by OID) to obtain hashlib constructors directly.
"""


class OIDException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)


# Maps OID dotted-string to a human-readable algorithm name.
OID = {
    "1.3.14.3.2.26":            "sha1",
    "2.16.840.1.101.3.4.2.4":   "sha224",
    "2.16.840.1.101.3.4.2.1":   "sha256",
    "2.16.840.1.101.3.4.2.2":   "sha384",
    "2.16.840.1.101.3.4.2.3":   "sha512",
    "1.2.840.113549.1.1.1":     "RSA (PKCS #1 v1.5)",
}

OIDrevert = {v: k for k, v in OID.items()}
