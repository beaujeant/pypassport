import os
import shutil
import tempfile
import subprocess
import logging


class OpenSSLException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)


class OpenSSL:

    def __init__(self, config="", opensslLocation="openssl"):
        self._opensslLocation = opensslLocation
        self._config = config

    @property
    def location(self):
        return self._opensslLocation

    @location.setter
    def location(self, value):
        self._opensslLocation = value

    def signData(self, sodContent, ds, dsKey):
        tmpdir = tempfile.mkdtemp()
        try:
            p12 = self.toPKCS12(ds, dsKey, "titus")
            dsDer = self.x509ToDER(ds)

            sodcontent_path = os.path.join(tmpdir, "sodContent")
            p12_path = os.path.join(tmpdir, "p12")
            dscer_path = os.path.join(tmpdir, "ds.cer")
            signed_path = os.path.join(tmpdir, "signed")

            self._toDisk(sodcontent_path, sodContent)
            self._toDisk(p12_path, p12)
            self._toDisk(dscer_path, dsDer)

            jar_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "createSod.jar")
            cmd = (
                "java -jar " + jar_path +
                " --certificate " + dscer_path +
                " --content " + sodcontent_path +
                " --keypass titus --privatekey " + p12_path +
                " --out " + signed_path
            )
            # NOTE: shell=True is used; paths come from caller-controlled data
            self._execute_raw(cmd, True)
            with open(signed_path, "rb") as f:
                res = f.read()
            return res
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def genRSAprKey(self, size):
        """
        Return an RSA private key of the specified size in PEM format.
        """
        return self._execute("genrsa " + str(size))

    def genRootX509(self, cscaKey, validity="", distinguishedName=None):
        """
        Generate a x509 self-signed certificate in PEM format
        """
        tmpdir = tempfile.mkdtemp()
        try:
            if distinguishedName:
                subj = distinguishedName.getSubject()
            else:
                from pypassport.pki import DistinguishedName
                subj = DistinguishedName(C="BE", O="Gouv", CN="CSCA-BELGIUM").getSubject()

            csca_key_path = os.path.join(tmpdir, "csca.key")
            self._toDisk(csca_key_path, cscaKey)
            cmd = "req -new -x509 -key " + csca_key_path + " -batch -text"
            if self._config:
                cmd += " -config " + self._config
            if subj:
                cmd += " -subj " + subj
            if validity:
                cmd += " -days " + str(validity)
            return self._execute(cmd)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def genX509Req(self, dsKey, distinguishedName=None):
        """
        Generate a x509 request in PEM format
        """
        tmpdir = tempfile.mkdtemp()
        try:
            if distinguishedName:
                subj = distinguishedName.getSubject()
            else:
                from pypassport.pki import DistinguishedName
                subj = DistinguishedName(C="BE", O="Gouv", CN="Document Signer BELGIUM").getSubject()

            ds_key_path = os.path.join(tmpdir, "ds.key")
            self._toDisk(ds_key_path, dsKey)
            cmd = "req -new -key " + ds_key_path + " -batch"
            if self._config:
                cmd += " -config " + self._config
            if subj:
                cmd += " -subj " + str(subj)
            return self._execute(cmd)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def signX509Req(self, csr, csca, cscaKey, validity=""):
        """
        Sign the request with the root certificate. Return a x509 certificate in PEM format

        @param csr: The certificate request
        @param csca: The root certificate
        @param cscaKey: The CA private key
        @param validity: The validity of the signed certificate
        """
        tmpdir = tempfile.mkdtemp()
        try:
            ds_csr_path = os.path.join(tmpdir, "ds.csr")
            csca_pem_path = os.path.join(tmpdir, "csca.pem")
            csca_key_path = os.path.join(tmpdir, "csca.key")
            self._toDisk(ds_csr_path, csr)
            self._toDisk(csca_pem_path, csca)
            self._toDisk(csca_key_path, cscaKey)
            cmd = "ca -in " + ds_csr_path + " -keyfile " + csca_key_path + " -cert " + csca_pem_path + "  -batch"
            if self._config:
                cmd += " -config " + self._config
            if validity:
                cmd += " -days " + str(validity)
            return self._execute(cmd)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def genCRL(self, csca, cscaKey):
        """
        @param csca: The root certificate
        @param cscaKey: The CA private key
        """
        tmpdir = tempfile.mkdtemp()
        try:
            csca_pem_path = os.path.join(tmpdir, "csca.pem")
            csca_key_path = os.path.join(tmpdir, "csca.key")
            self._toDisk(csca_pem_path, csca)
            self._toDisk(csca_key_path, cscaKey)
            cmd = "ca -gencrl -cert " + csca_pem_path + " -keyfile " + csca_key_path
            if self._config:
                cmd += " -config " + self._config
            return self._execute(cmd)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def revokeX509(self, cert, csca, cscaKey):
        """
        @param csca: The root certificate
        @param cscaKey: The CA private key
        """
        tmpdir = tempfile.mkdtemp()
        try:
            torevoke_path = os.path.join(tmpdir, "toRevoke")
            csca_pem_path = os.path.join(tmpdir, "csca.pem")
            csca_key_path = os.path.join(tmpdir, "csca.key")
            self._toDisk(torevoke_path, cert)
            self._toDisk(csca_pem_path, csca)
            self._toDisk(csca_key_path, cscaKey)
            cmd = "ca -revoke " + torevoke_path + " -cert " + csca_pem_path + " -keyfile " + csca_key_path
            if self._config:
                cmd += " -config " + self._config
            return self._execute(cmd, True)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def toPKCS12(self, certif, prK, pwd):
        """
        Return a RSA key pair under the PKCS#12 format.
        PKCS#12: used to store private keys with accompanying public key certificates, protected with a password-based symmetric key
        """
        tmpdir = tempfile.mkdtemp()
        try:
            certif_path = os.path.join(tmpdir, "certif")
            prk_path = os.path.join(tmpdir, "prK")
            self._toDisk(certif_path, certif)
            self._toDisk(prk_path, prK)
            return self._execute("pkcs12 -export -in " + certif_path + " -inkey " + prk_path + " -passout pass:" + pwd)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def x509ToDER(self, certif):
        tmpdir = tempfile.mkdtemp()
        try:
            pem_path = os.path.join(tmpdir, "pem")
            self._toDisk(pem_path, certif)
            return self._execute("x509 -in " + pem_path + " -outform DER")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def prRSAToDERPb(self, prKey):
        """
        Retrieve the corresponding DER encoded public key from the given RSA private key
        """
        tmpdir = tempfile.mkdtemp()
        try:
            dg15_path = os.path.join(tmpdir, "dg15")
            self._toDisk(dg15_path, prKey)
            return self._execute("rsa -pubout -in " + dg15_path + " -outform der")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def RSAKeyToText(self, key):
        """
        Convert a key to its text format
        """
        tmpdir = tempfile.mkdtemp()
        try:
            key_path = os.path.join(tmpdir, "key")
            self._toDisk(key_path, key)
            return self._execute("rsa -text -in " + key_path)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def crlToDER(self, crl):
        tmpdir = tempfile.mkdtemp()
        try:
            crl_path = os.path.join(tmpdir, "crl")
            self._toDisk(crl_path, crl)
            return self._execute("crl -inform PEM -in " + crl_path + " -outform DER")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def _toDisk(self, path, data=None):
        with open(path, "wb") as f:
            if data is not None:
                f.write(data)

    def _execute(self, toExecute, empty=False):
        # NOTE: shell=True is intentional for compatibility; paths originate from
        # caller-controlled configuration and are not sanitised against shell injection.
        cmd = self._opensslLocation + " " + toExecute
        logging.debug(cmd)
        return self._execute_raw(cmd, empty)

    def _execute_raw(self, cmd, empty=False):
        # NOTE: shell=True is intentional; see _execute comment.
        logging.debug(cmd)
        res = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out = res.stdout.read()
        err = res.stderr.read()

        if ((not out) and err and not empty):
            raise OpenSSLException(err)

        return out

    def _isOpenSSL(self):
        cmd = "version"
        try:
            return self._execute(cmd)
        except OpenSSLException:
            return False

    def printCrl(self, crl):
        tmpdir = tempfile.mkdtemp()
        try:
            crl_path = os.path.join(tmpdir, "crl")
            self._toDisk(crl_path, crl)
            cmd = "crl -in " + crl_path + " -text -noout -inform DER"
            return self._execute(cmd)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
