# © 2017 Creu Blanca
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).

import hashlib
import logging
from base64 import b64decode, b64encode

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_der_x509_certificate
from lxml.builder import ElementMaker
from xades.constants import MAP_HASHLIB, NS_MAP
from xades.ns import EtsiNS
from xades.utils import dict_compare, rdns_to_map
from xmlsig.constants import TransformSha1, TransformUsageDigestMethod
from xmlsig.ns import DSigNs
from xmlsig.utils import USING_PYTHON2, create_node, get_rdns_name

if USING_PYTHON2:
    import urllib
else:
    import urllib.request as urllib

logger = logging.getLogger(__name__)


ETSI = ElementMaker(namespace=EtsiNS)
DS = ElementMaker(namespace=DSigNs)


class BasePolicy(object):
    """"
    Policy base class created in order to define different policies.
    A mixture of base class implementations, and abstract class
    interface definitions. (TODO: might be separated in the future)
    """

    hash_method = None

    @property
    def identifier(self):
        raise NotImplementedError("Implement on specific subclasses")

    @property
    def name(self):
        raise NotImplementedError("Implement on specific subclasses")

    @property
    def policy(self):
        raise NotImplementedError("Implement on specific subclasses")

    def _resolve_policy(self, identifier):
        """
        Resolves the signature policy to bytes.
        Override for resolving e.g. from a local cache
        :param identifier: the value of <etsi:SigPolicyId/etsi:Identifier/>
        :return: bytes
        """
        return urllib.urlopen(identifier).read()

    def sign(self, signature):
        return

    def validate(self, signature):
        """
        Finds if the policy is the same and then applies the policy validation.
        Otherwise, it does nothing
        :param signature: Signature node
        :return:
        """
        policy = signature.find(
            "ds:Object/etsi:QualifyingProperties/etsi:SignedProperties/"
            "etsi:SignedSignatureProperties/etsi:SignaturePolicyIdentifier/"
            "etsi:SignaturePolicyId",
            namespaces=NS_MAP,
        )
        if policy is None:
            return
        if self.identifier != policy.find(
            "etsi:SigPolicyId/etsi:Identifier", namespaces=NS_MAP
        ):
            return
        self.validate_policy(signature)

    def validate_policy(self, signature):
        """
        Policy validation
        :param signature: signature node
        :return: None
        """
        return

    def set_transforms(self, transforms, value, sign=False):
        """
        Creates transformations of the policy if required. Modifies node and
        returns the transformed value
        :param node: Policy node
        :param value: Original value
        :param sign: Calculates or validates the transformation
        :return: str
        """
        return value

    def _query_signature_policy_identifer_data(self, node):
        """
        Query common policy validation data.
        """
        signature_policy_id = node.find("etsi:SignaturePolicyId", namespaces=NS_MAP)
        sig_policy_id = signature_policy_id.find("etsi:SigPolicyId", namespaces=NS_MAP)
        identifier = sig_policy_id.find("etsi:Identifier", namespaces=NS_MAP).text
        hash_method = signature_policy_id.find(
            "etsi:SigPolicyHash/ds:DigestMethod", namespaces=NS_MAP
        ).get("Algorithm")
        digest_value = signature_policy_id.find(
            "etsi:SigPolicyHash/ds:DigestValue", namespaces=NS_MAP
        ).text
        transforms = signature_policy_id.find("ds:Tranforms", namespaces=NS_MAP)
        return {
            "Identifier": identifier,
            "DigestMethodAlgorithm": hash_method,
            "DigestValue": digest_value,
            "Transforms": transforms,
        }

    def validate_policy_node(self, node):
        """
        A validation implementation for a given
        <etsi:SignaturePolicyIdentifier/> node
        :param node: Policy node
        :return: bool
        """
        raise NotImplementedError("Implement on specific subclasses")

    def calculate_certificates(self, node, keys_x509):
        for key_x509 in keys_x509:
            self.calculate_certificate(node, key_x509)

    def calculate_certificate(self, node, key_x509):
        fingerprint = key_x509.fingerprint(MAP_HASHLIB[self.hash_method]())
        _ETSI_Cert = ETSI.Cert(
            ETSI.CertDigest(
                DS.DigestMethod(Algorithm=self.hash_method),
                DS.DigestValue(b64encode(fingerprint).decode()),
            ),
            ETSI.IssuerSerial(
                DS.X509IssuerName(get_rdns_name(key_x509.issuer.rdns)),
                DS.X509SerialNumber(str(key_x509.serial_number)),
            ),
        )
        node.append(_ETSI_Cert)

    def validate_certificate(self, node, signature):
        certs = node.findall("etsi:Cert", namespaces=NS_MAP)
        x509 = signature.find("ds:KeyInfo/ds:X509Data", namespaces=NS_MAP)
        x509_data = x509.find("ds:X509Certificate", namespaces=NS_MAP)
        serial = x509.find("ds:X509IssuerSerial", namespaces=NS_MAP)
        if serial is not None:
            serial_name = serial.find("ds:X509IssuerName", namespaces=NS_MAP).text
            serial_number = serial.find("ds:X509SerialNumber", namespaces=NS_MAP).text
            certificate = None
            for cert in certs:
                if (
                    cert.find(
                        "etsi:IssuerSerial/ds:X509IssuerName", namespaces=NS_MAP
                    ).text
                    == serial_name
                    and cert.find(
                        "etsi:IssuerSerial/ds:X509SerialNumber", namespaces=NS_MAP
                    ).text
                    == serial_number
                ):
                    certificate = cert
            assert certificate is not None
        else:
            certificate = certs[0]
        if x509_data is not None:
            parsed_x509 = load_der_x509_certificate(
                b64decode(x509_data.text), default_backend()
            )
            assert (
                str(parsed_x509.serial_number)
                == certificate.find(
                    "etsi:IssuerSerial/ds:X509SerialNumber", namespaces=NS_MAP
                ).text
            )
            dict_compare(
                rdns_to_map(get_rdns_name(parsed_x509.issuer.rdns)),
                rdns_to_map(
                    certificate.find(
                        "etsi:IssuerSerial/ds:X509IssuerName", namespaces=NS_MAP
                    ).text
                ),
            )
            digest = certificate.find("etsi:CertDigest", namespaces=NS_MAP)
            assert (
                b64encode(
                    parsed_x509.fingerprint(
                        MAP_HASHLIB[
                            digest.find("ds:DigestMethod", namespaces=NS_MAP).get(
                                "Algorithm"
                            )
                        ]()
                    )
                ).decode()
                == digest.find("ds:DigestValue", namespaces=NS_MAP).text
            )

    def calculate_policy_node(self, node, sign=False):
        """
        Calculates de policy node
        :param node: SignaturePolicyIdentifier node
        :param sign: checks if we must calculate or validate a policy
        :return:
        """
        logger.warning(
            "This method is deprecated. Use `produce_policy_node` "
            "or `validate_policy_node` accordingly."
        )
        if not sign:
            return self.validate_policy_node(node)
        return self.produce_policy_node(node)


class ImpliedPolicy(BasePolicy):
    def __init__(self, hash_method=TransformSha1):
        self.hash_method = hash_method

    @property
    def identifier(self):
        return None

    def produce_policy_node(self, node):
        """
        Produces the policy node
        :param node: SignaturePolicyIdentifier node
        :return:
        """
        create_node("SignaturePolicyImplied", node, EtsiNS)

    def validate_policy_node(self, node):
        """
        A specific validation implementation for a given
        <etsi:SignaturePolicyIdentifier/> node
        Implied policy by itself cannot be validated
        :param node: Policy node
        :return:
        """
        return


class GenericPolicyId(BasePolicy):
    def __init__(self, identifier, name, hash_method):
        self.generic_identifier = identifier
        self.generic_name = name
        self.hash_method = hash_method
        self._policy = None

    @property
    def identifier(self):
        return self.generic_identifier

    @property
    def name(self):
        return self.generic_name

    @property
    def policy(self):
        if not self._policy:
            self._policy = self._resolve_policy(self.identifier)
        return self._policy

    def produce_policy_node(self, node):
        """
        Produces the policy node
        :param node: SignaturePolicyIdentifier node
        :return:
        """
        value = self._resolve_policy(self.identifier)
        # Must be previously set in the template
        # TODO: Implement a better version
        transforms = node.find(
            "etsi:SignaturePolicyId/ds:Transforms", namespaces=NS_MAP
        )
        value = self.set_transforms(transforms, value, True)
        hash_calc = hashlib.new(TransformUsageDigestMethod[self.hash_method])
        hash_calc.update(value)
        _ETSI_SignaturePolicyId = ETSI.SignaturePolicyId(
            ETSI.SigPolicyId(ETSI.Identifier(), ETSI.Description()),
            ETSI.SigPolicyHash(
                DS.DigestMethod(Algorithm=self.hash_method),
                DS.DigestValue(b64encode(hash_calc.digest()).decode()),
            ),
        )
        node.append(_ETSI_SignaturePolicyId)

    def validate_policy_node(self, node):
        """
        A specifc validation implementation for a given
        <etsi:SignaturePolicyIdentifier/> node leveraging known cached policy
        :param node: Policy node
        :return: bool
        """
        implied = node.find("etsi:SignaturePolicyImplied", namespaces=NS_MAP)
        if implied is not None:
            return
        data = self._query_signature_policy_identifer_data(node)
        value = self.policy
        value = self.set_transforms(data["Transforms"], value, False)
        hash_calc = hashlib.new(
            TransformUsageDigestMethod[data["DigestMethodAlgorithm"]]
        )
        hash_calc.update(value)
        assert data["DigestValue"] == b64encode(hash_calc.digest()).decode()
