import os
import os.path

CertFormat = ["DER", "PEM"]

class CAManager(object):
    """
    This object is used for the certificate validation.
    It encapsulates the certificates directory and performs the certificate name conversion in its hash.0 format.
    """
    def __init__(self, dir):
        """
        @param dir: The directory with the root certificates
        @type dir: A string
        """
        self._dir = dir

    def toHashes(self):
        """
        For each certificate, create a new certificate named with the hash value of the issuer followed with .0
        By this way, the corresponding CSCA certificate of the DS certificate can be found easily by openSSL.
        """
        #TODO See c_rehash what it does and implement the same...
        # ePV looks for .cer but getHash accepts both DER & PEM formats
        # then hash copy is converted to PEM but what is required for openssl?
        # If I delete *cer it fails, so why having to keep redundant data?
        existing = False
        for fileName in os.listdir(self.dir):
            file = self.dir + os.path.sep + fileName

            if not fileName.endswith(".0") and fileName.endswith(".cer"):
                existing = True
                (hash, format) = self._getHash(file)
                hashName = hash + os.path.extsep + "0"
                self._toPEM(file, format, hashName, self.dir + os.path.sep)

        if not existing:
            raise Exception("No certificate (*.cer) has been found.")

    def _getHash(self, file):
        """
        Calculate the hash of the specified certificate.

        @param file: The url of the certificate
        @type file: A string
        """
        data = None
        format = None
        for format in CertFormat:
            #TODO: Deplacer le code openssl dans OpenSSL
            a = "openssl x509 -hash -in "+ file +" -inform "+format + " -noout"
            r = os.popen(a, "rb")
            data = r.read().strip()
            r.close()
            f = format
            if data: break

        if not data:
            raise Exception("The certificate format is unknown for file: " + str(file) + "\nor OpenSSL is not set")
        return (data, format)

    def _toPEM(self, certif, format, name, path):
        """
        Convert the certificate into the PEM format.
        If the certificate is already in PEM, do nothing.

        @param certif: The url of the certificate to convert in PEM
        @type certif: A string
        @param format: The format of the certificate, must be DER or PEM
        @type format: A string
        @param name: The name of the resulting certificate
        @type name: A string
        @param path: The path where to store the certificate
        @type path: A string

        @raise Exception: If the format parameter is not DER or PEM
        """
#        if format == "PEM": return certif
#        if format != "DER": raise Exception("Bad certificate format")

        a = "openssl x509 -in " + certif + " -inform " + format + " -outform PEM " + " -out " + path + name
        r = os.popen(a, "rb")
        data = r.read().strip()
        r.close()

        return data

    def _getDir(self):
        """
        Return the url of the directory where the certificates are stored.
        """
        return self._dir

    dir = property(_getDir)
