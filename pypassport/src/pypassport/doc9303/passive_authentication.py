from __future__ import annotations

import logging
import hashlib
from typing import Any, TypedDict

from pyasn1.codec.der import decoder
from pypassport import hex_utils
from pypassport.doc9303 import converter
from pypassport.doc9303 import data_group
from pypassport.der_object_identifier import OID, OIDException
from pypassport.ca_manager import CAManager
from pypassport.doc9303 import cms
from pypassport import asn1


# Dispatch table mapping OID strings directly to hashlib constructors.
# Replaces the previous eval(OID[oid]) pattern.
_HASH_ALGORITHMS = {
    "1.3.14.3.2.26": hashlib.sha1,
    "2.16.840.1.101.3.4.2.4": hashlib.sha224,
    "2.16.840.1.101.3.4.2.1": hashlib.sha256,
    "2.16.840.1.101.3.4.2.2": hashlib.sha384,
    "2.16.840.1.101.3.4.2.3": hashlib.sha512,
}


class PassiveAuthenticationException(Exception):
    pass


class LDSContent(TypedDict):
    version: str
    hashAlgorithm: str
    dataGroupHashValues: dict[str, bytes]


class PassiveAuthentication:
    """
    This class implements the passive authentication protocol.
    The two main methods are I{verify_sod_and_cds} and I{execute_pa}. The first verifies the SOD and the CDS and retrieves the relevant dataGroups
    from the LDS, that's why this method must be called before I{execute_pa} that uses these extracted informations to calculate the hashes.
    Even if the Certificate validation failed, it does not mean that the data could not be retrieved from the LDS.
    """

    def __init__(self):
        self._content: LDSContent | None = None
        self._data: bytes | None = None
        self._info: cms.SignedDataInfo | None = None
        self._sod_body: bytes | None = None
        self._verification_info: dict[str, Any] | None = None

    def _parse(self, sodObj):
        """Parse (and cache) the SOD's CMS SignedData into a SignedDataInfo."""
        if not isinstance(sodObj, data_group.SOD):
            raise PassiveAuthenticationException("sodObj must be a sod object")
        if sodObj.body is None:
            raise PassiveAuthenticationException("sodObj object is not initialized")
        if self._info is None or self._sod_body != sodObj.body:
            try:
                self._info = cms.parse_sod(sodObj.body)
            except cms.CMSVerificationException as msg:
                raise PassiveAuthenticationException(str(msg))
            self._sod_body = sodObj.body
        return self._info

    def verify_sod_and_cds(self, sodObj, csca_directory):
        """
        Execute the first part of the Passive Authentication protocol.
            - Read the document signer from the Document Security Object
            - Verify SOD by using Document Signer Public Key (KPuDS).
            - Verify CDS by using the Country Signing CA Public Key (KPuCSCA).
            - Read the relevant Data Groups from the LDS.

        @param sodObj: An initialized security data object
        @type sodObj: A sod object
        @param csca_directory: The object representing the CSCA directory.
        @type csca_directory: A CAManager object

        @return: True if the DS Certificate is valided

        @raise PassiveAuthenticationException: I{sodObj must be a sod object}: the sodObj parameter must be a sod object.
        @raise PassiveAuthenticationException: I{sodObj object is not initialized}: the sodObj parameter is a sod object, but is not initialized.
        @raise PassiveAuthenticationException: I{csca_directory is not set}
        """

        if csca_directory is None:
            raise PassiveAuthenticationException("csca_directory is not set")

        if not isinstance(sodObj, data_group.SOD):
            raise PassiveAuthenticationException("sodObj must be a sod object")

        if not isinstance(csca_directory, CAManager):
            raise PassiveAuthenticationException("csca_directory must be a CAManager object")

        self._verification_info = None
        info = self._parse(sodObj)

        self._data = info.econtent
        self._content = self._read_dg_from_lds(self._data)

        # Verify the Document Signer's signature over the SOD content. OpenSSL
        # only ever extracted the content (smime -verify -noverify); this check
        # was previously missing and is performed natively here.
        try:
            cms.verify_sod_signature(info)
        except cms.CMSVerificationException as msg:
            raise PassiveAuthenticationException("SOD signature verification failed: " + str(msg))

        # Verify the Document Signer Certificate against the trusted CSCA store.
        matched_csca_der = self.verify_dsc(info.dsc_der, csca_directory)
        self._verification_info = {
            "sod": {
                "econtent_type_oid": info.econtent_type,
                "digest_algorithm_oid": info.digest_algorithm,
                "digest_algorithm": OID.get(info.digest_algorithm, info.digest_algorithm),
                "signature_algorithm_oid": info.signature_algorithm,
                "signature_algorithm": OID.get(info.signature_algorithm, info.signature_algorithm),
            },
            "document_signer_certificate": cms.certificate_summary(info.dsc_der),
            "country_signing_ca_certificate": cms.certificate_summary(matched_csca_der),
        }
        dsc = self._verification_info["document_signer_certificate"]
        logging.info(
            "SOD verified with DSC subject=%s serial=%s issuer=%s",
            dsc["subject"],
            dsc["serial_number"],
            dsc["issuer"],
        )
        return True

    def execute_pa(self, sodObj, dgs):
        """
        Execute the second part of the Passive Authentication protocol
            - Calculate the hashes of the given Data Groups.
            - Compare the calculated hashes with the corresponding hash values in the SOD.

        @param sodObj: An initialized security data object
        @type sodObj: A sod object
        @param dgs: A list of dataGroup objects to verify
        @type dgs: A list of dataGroup
        @return: The dictionary is indexed with the DataGroup name (DG1...DG15) and the value is a boolean: True if the check is ok.
        @raise PassiveAuthenticationException: I{sodObj must be a sod object}: the sodObj parameter must be a sod object.
        @raise PassiveAuthenticationException: I{sodObj object is not initialized}: the sodObj parameter is a sod object, but is not initialized.
        """

        if self._data is None:
            self._data = self.get_sod_content(sodObj)

        if self._content is None:
            self._content = self._read_dg_from_lds(self._data)

        hashes = self._calculate_hashes(dgs)
        return self._compare_hashes(hashes)

    def get_sod_content(self, sodObj):
        """
        Return the signed content (LDSSecurityObject) embedded in the SOD.

        @param sodObj: A filled SOD object
        @type sodObj: A sod object
        @return: The LDSSecurityObject DER bytes.
        @raise PassiveAuthenticationException: I{sodObj must be a sod object}: the sodObj parameter must be a sod object.
        @raise PassiveAuthenticationException: I{sodObj object is not initialized}: the sodObj parameter is a sod object, but is not initialized.
        """
        logging.debug("Extract the signed content (LDSSecurityObject) from the SOD")
        return self._parse(sodObj).econtent

    def verify_dsc(self, CDS, csca_directory):
        """
        Verify the Document Signer Certificate against the trusted CSCA store.

        @param CDS: The document signer certificate (DER or PEM bytes).
        @param csca_directory: A CAManager wrapping the trusted CSCA directory,
            or an iterable of trusted CSCA certificates (DER/PEM bytes).
        @return: The DER bytes of the trusted CSCA certificate that validated
            the Document Signer Certificate.
        @raise PassiveAuthenticationException: I{The CDS is not set}: The CDS parameter must be a non-empty string.
        @raise PassiveAuthenticationException: I{The CA is not set}: The csca_directory parameter must be set.
        @raise PassiveAuthenticationException: If the certificate chain cannot be validated.
        """

        logging.debug("Verify CDS by using the Country Signing CA Public Key (KPuCSCA). ")

        if not CDS:
            raise PassiveAuthenticationException("The CDS is not set")

        if csca_directory is None:
            raise PassiveAuthenticationException("The CA is not set")

        if isinstance(csca_directory, CAManager):
            csca_ders = csca_directory.get_certificates()
        else:
            csca_ders = [
                cms.load_certificate_der(c if isinstance(c, (bytes, bytearray)) else c.encode()) for c in csca_directory
            ]

        if isinstance(CDS, (bytes, bytearray)):
            dsc_der = cms.load_certificate_der(bytes(CDS))
        else:
            dsc_der = cms.load_certificate_der(CDS.encode())

        try:
            return cms.verify_chain_with_issuer(dsc_der, csca_ders)
        except cms.CMSVerificationException as msg:
            raise PassiveAuthenticationException(str(msg))

    @property
    def verification_info(self) -> dict[str, Any] | None:
        """Details about the last successful SOD / DSC verification."""

        return self._verification_info

    def get_certificate(self, sodObj):
        """
        Retrieve the Document Signer certificate out of the SOD.
        @return: A PEM representation of the certificate.
        @raise PassiveAuthenticationException: I{sodObj must be a sod object}: the sodObj parameter must be a sod object.
        @raise PassiveAuthenticationException: I{sodObj object is not initialized}: the sodObj parameter is a sod object, but is not initialized.
        """
        return cms.certificate_to_pem(self._parse(sodObj).dsc_der)

    def _read_dg_from_lds(self, data):
        """
        Read the relevant Data Groups from the LDS

        @param data: The content of the verified signature.
        @type data:  A binary string
        @return: A dictionary with the parsed data of the signature (version, hashAlgorithm and dataGrouphashValues)
        """
        logging.debug("Read the relevant Data Groups from the LDS")

        content: LDSContent = {
            "version": "",
            "hashAlgorithm": "",
            "dataGroupHashValues": {},
        }
        dg_hashes: dict[str, bytes] = {}

        certType = asn1.LDSSecurityObject()
        cert = decoder.decode(data, asn1Spec=certType)[0]

        content["version"] = cert.getComponentByName("version").prettyPrint()
        content["hashAlgorithm"] = (
            cert.getComponentByName("hashAlgorithm").getComponentByName("algorithm").prettyPrint()
        )

        for h in cert.getComponentByName("dataGroupHashValues"):
            dg_hashes[h.getComponentByName("dataGroupNumber").prettyPrint()] = h.getComponentByName(
                "dataGroupHashValue"
            ).asOctets()

        content["dataGroupHashValues"] = dg_hashes

        return content

    def _calculate_hashes(self, dgs):
        """
        Calculate the hashes of the relevant Data Groups, theses presents in the signature.

        @param dgs: A list of dataGroup objects to calculate the hash values.
        @type dgs: A list.
        @return: A dictionary indexed with DG1..DG15 with the calculated hashes of the DGs.
        """
        logging.debug("Calculate the hashes of the relevant Data Groups")
        hashes: dict[str, bytes] = {}
        # Find the hash function from the content dictionary
        hash_fn = self._get_hash_algorithm()
        for dg in dgs:
            res = hash_fn(dg.file)
            hashes[converter.to_dg(dg.tag)] = res.digest()

        return hashes

    def _compare_hashes(self, hashes):
        """
        Compare the calculated hashes with the corresponding hashes present in the SOD.

        @param hashes: A dictionary of hashes to compare with the security object hashes.
        @type hashes: A dictionary
        @return: A dictionary indexed with the DG name (DG1..DG15) and with the result of the hash comparison (True or False, None if the DG is not present in the SOD)
        """
        logging.debug("Compare the calculated hashes with the corresponding hash values in the SOD")

        content = self._require_content()
        res: dict[str, bool | None] = {}

        for dg in hashes:
            try:
                res[converter.to_dg(dg)] = hashes[dg] == content["dataGroupHashValues"][converter.to_other(dg)]
            except KeyError:
                res[converter.to_dg(dg)] = None

        return res

    def _get_hash_algorithm(self):
        """
        Return the object corresponding to the hash algorithm used to calculate the hashes present in the SOD.
        @return: The object corresponding to the hash algorithm, or an oidException if not found.
        """
        if self._content is None:
            raise PassiveAuthenticationException("The object is not set. Call init first.")
        return self._get_algo_by_oid(self._content["hashAlgorithm"])

    def _require_content(self) -> LDSContent:
        if self._content is None:
            raise PassiveAuthenticationException("The object is not set. Call init first.")
        return self._content

    def _get_algo_by_oid(self, oid):
        hash_fn = _HASH_ALGORITHMS.get(oid)
        if hash_fn is None:
            raise OIDException("No such algorithm for OID " + str(oid))
        return hash_fn

    def __str__(self):
        content = self._require_content()
        res = "version: " + content["version"] + "\n"
        res += (
            "Hash algorithm: "
            + OID.get(content["hashAlgorithm"], content["hashAlgorithm"])
            + " ("
            + content["hashAlgorithm"]
            + ")\n"
        )
        res += "Data group hash values: " + "\n"

        for dghv in content["dataGroupHashValues"].keys():
            res += "Data group: " + converter.to_ef(dghv) + "\n"
            res += "Hash value: " + hex_utils.bin_to_hex_rep(content["dataGroupHashValues"][dghv]) + "\n"

        return res
