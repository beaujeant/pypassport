"""DER Object Identifier (OID) lookup table for passport algorithms."""


class OIDException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)


# Maps OID dotted-string to a human-readable algorithm name.
OID = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.4": "sha224",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
    "1.2.840.113549.1.1.1": "RSA (PKCS #1 v1.5)",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.1": "ecdsa-with-SHA224",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    # BSI TR-03111 plain-format ECDSA signatures.  European travel documents
    # commonly use these instead of the X9.62 DER signature OIDs above.
    "0.4.0.127.0.7.1.1.4.1.1": "ecdsa-plain-SHA1",
    "0.4.0.127.0.7.1.1.4.1.2": "ecdsa-plain-SHA224",
    "0.4.0.127.0.7.1.1.4.1.3": "ecdsa-plain-SHA256",
    "0.4.0.127.0.7.1.1.4.1.4": "ecdsa-plain-SHA384",
    "0.4.0.127.0.7.1.1.4.1.5": "ecdsa-plain-SHA512",
    "0.4.0.127.0.7.1.1.4.1.6": "ecdsa-plain-RIPEMD160",
}
