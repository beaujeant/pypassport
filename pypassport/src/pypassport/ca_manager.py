import os
import os.path

_CERT_EXTENSIONS = (".cer", ".der", ".crt", ".pem")


class CAManagerException(Exception):
    pass


class CAManager(object):
    """
    This object is used for the certificate validation.
    It encapsulates the directory holding the trusted CSCA certificates.
    """
    def __init__(self, dir):
        """
        @param dir: The directory with the root certificates
        @type dir: A string
        """
        self._dir = dir

    def toHashes(self):
        """
        Verify that the directory contains at least one certificate.

        Issuer lookup is now done in pure Python by matching Distinguished
        Names (see L{pypassport.pa_crypto.verify_certificate_chain}), so no
        OpenSSL-style C{<hash>.0} copies need to be created.

        @raise CAManagerException: If no certificate is present in the directory.
        """
        for fileName in os.listdir(self.dir):
            if fileName.lower().endswith(_CERT_EXTENSIONS):
                return

        raise CAManagerException("No certificate has been found.")

    def _getDir(self):
        """
        Return the url of the directory where the certificates are stored.
        """
        return self._dir

    dir = property(_getDir)
