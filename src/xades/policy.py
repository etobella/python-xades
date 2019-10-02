# -*- coding: utf-8 -*-
# © 2017 Creu Blanca
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).

import hashlib
import logging
from base64 import b64decode, b64encode

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_der_x509_certificate

from xades.constants import NS_MAP, MAP_HASHLIB
from xades.ns import EtsiNS
from xades.utils import rdns_to_map, dict_compare
from xmlsig.constants import TransformUsageDigestMethod, TransformSha1
from xmlsig.ns import DSigNs
from xmlsig.utils import create_node, USING_PYTHON2, get_rdns_name

if USING_PYTHON2:
    import urllib
else:
    import urllib.request as urllib

logger = logging.getLogger(__name__)

class Policy(object):
    """"
    Policy class created in order to define different policies
    """
    hash_method = None

    @property
    def identifier(self):
        raise Exception("Id is not defined")

    @property
    def name(self):
        raise Exception("Name is not defined")

    @property
    def policy(self):
        raise Exception("Policy is not defined")

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
            'ds:Object/etsi:QualifyingProperties/etsi:SignedProperties/'
            'etsi:SignedSignatureProperties/etsi:SignaturePolicyIdentifier/'
            'etsi:SignaturePolicyId',
            namespaces=NS_MAP)
        if policy is None:
            return
        if self.identifier != policy.find(
                'etsi:SigPolicyId/etsi:Identifier', namespaces=NS_MAP):
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
        signature_policy_id = node.find('etsi:SignaturePolicyId', namespaces=NS_MAP)
        sig_policy_id = signature_policy_id.find('etsi:SigPolicyId', namespaces=NS_MAP)
        identifier = sig_policy_id.find('etsi:Identifier', namespaces=NS_MAP).text
        hash_method = signature_policy_id.find(
            'etsi:SigPolicyHash/ds:DigestMethod', namespaces=NS_MAP
        ).get('Algorithm')
        digest_value = signature_policy_id.find(
            'etsi:SigPolicyHash/ds:DigestValue', namespaces=NS_MAP
        ).text
        transforms = signature_policy_id.find('ds:Tranforms', namespaces=NS_MAP)
        return {
            "Identifier": identifier,
            "DigestMethodAlgorithm": hash_method,
            "DigestValue": digest_value,
            "Transforms": transforms
        }

    def validate_policy_node(self, node):
        """
        An unspecific validation implementation for a given
        <etsi:SignaturePolicyIdentifier/> node
        :param node: Policy node
        :return: bool
        """
        implied = node.find('etsi:SignaturePolicyImplied', namespaces=NS_MAP)
        if implied is not None:
            return
        data = self._query_signature_policy_identifer_data(node)
        value = self._resolve_policy(data['Identifier'])
        value = self.set_transforms(data['Transforms'], value, False)
        hash_calc = hashlib.new(
            TransformUsageDigestMethod[data['DigestMethodAlgorithm']])
        hash_calc.update(value)
        digest_val = hash_calc.digest()
        assert data['DigestValue'].encode() == b64encode(digest_val)

    def calculate_certificates(self, node, key_x509):
        self.calculate_certificate(node, key_x509)

    def calculate_certificate(self, node, key_x509):
        cert = create_node('Cert', node, EtsiNS)
        cert_digest = create_node('CertDigest', cert, EtsiNS)
        digest_algorithm = create_node('DigestMethod', cert_digest, DSigNs)
        digest_algorithm.set('Algorithm', self.hash_method)
        digest_value = create_node('DigestValue', cert_digest, DSigNs)
        digest_value.text = b64encode(key_x509.fingerprint(
            MAP_HASHLIB[self.hash_method]()
        ))
        issuer_serial = create_node('IssuerSerial', cert, EtsiNS)
        create_node(
            'X509IssuerName', issuer_serial, DSigNs
        ).text = get_rdns_name(key_x509.issuer.rdns)
        create_node(
            'X509SerialNumber', issuer_serial, DSigNs
        ).text = str(key_x509.serial_number)
        return

    def validate_certificate(self, node, signature):
        certs = node.findall('etsi:Cert', namespaces=NS_MAP)
        x509 = signature.find('ds:KeyInfo/ds:X509Data', namespaces=NS_MAP)
        x509_data = x509.find('ds:X509Certificate', namespaces=NS_MAP)
        serial = x509.find('ds:X509IssuerSerial', namespaces=NS_MAP)
        if serial is not None:
            serial_name = serial.find(
                'ds:X509IssuerName', namespaces=NS_MAP
            ).text
            serial_number = serial.find(
                'ds:X509SerialNumber', namespaces=NS_MAP
            ).text
            certificate = None
            for cert in certs:
                if cert.find(
                        'etsi:IssuerSerial/ds:X509IssuerName',
                        namespaces=NS_MAP
                ).text == serial_name and cert.find(
                    'etsi:IssuerSerial/ds:X509SerialNumber',
                    namespaces=NS_MAP
                ).text == serial_number:
                    certificate = cert
            assert certificate is not None
        else:
            certificate = certs[0]
        if x509_data is not None:
            parsed_x509 = load_der_x509_certificate(
                b64decode(x509_data.text), default_backend()
            )
            assert str(parsed_x509.serial_number) == certificate.find(
                'etsi:IssuerSerial/ds:X509SerialNumber', namespaces=NS_MAP
            ).text
            dict_compare(
                rdns_to_map(get_rdns_name(parsed_x509.issuer.rdns)),
                rdns_to_map(certificate.find(
                    'etsi:IssuerSerial/ds:X509IssuerName',
                    namespaces=NS_MAP
                ).text)
            )
            digest = certificate.find(
                'etsi:CertDigest', namespaces=NS_MAP
            )
            assert b64encode(
                parsed_x509.fingerprint(MAP_HASHLIB[digest.find(
                    'ds:DigestMethod', namespaces=NS_MAP
                ).get('Algorithm')]())) == digest.find(
                'ds:DigestValue', namespaces=NS_MAP).text.encode()

    def calculate_policy_node(self, node, sign=False):
        """
        Calculates de policy node
        :param node: SignaturePolicyIdentifier node
        :param sign: checks if we must calculate or validate a policy
        :return:
        """
        logger.warning(
            "This method is deprecated. Use `produce_policy_node` "
            "or `validate_policy_node` accordingly.")
        if not sign:
            return self.validate_policy_node(node)
        return self.produce_policy_node(node)


class ImpliedPolicy(Policy):
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
        create_node('SignaturePolicyImplied', node, EtsiNS)

    def validate_policy_node(self, node):
        """
        A specific validation implementation for a given
        <etsi:SignaturePolicyIdentifier/> node
        Implied policy by itself cannot be validated
        :param node: Policy node
        :return:
        """
        return


class GenericPolicyId(Policy):
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
        signature_policy_id = create_node('SignaturePolicyId', node, EtsiNS)
        sig_policy_id = create_node('SigPolicyId', signature_policy_id, EtsiNS)
        create_node('Identifier', sig_policy_id, EtsiNS).text = self.identifier
        create_node('Description', sig_policy_id, EtsiNS).text = self.name
        value = self._resolve_policy(self.identifier)
        value = self.set_transforms(signature_policy_id, value, sign)
        digest = create_node('SigPolicyHash', signature_policy_id, EtsiNS)
        digest_method = create_node('DigestMethod', digest, DSigNs)
        digest_method.set('Algorithm', self.hash_method)
        digest_value = create_node('DigestValue', digest, DSigNs)
        hash_calc = hashlib.new(TransformUsageDigestMethod[self.hash_method])
        hash_calc.update(value)
        digest_value.text = b64encode(hash_calc.digest())

    def validate_policy_node(self, node):
        """
        A specifc validation implementation for a given
        <etsi:SignaturePolicyIdentifier/> node leveraging known cached policy
        :param node: Policy node
        :return: bool
        """
        implied = node.find('etsi:SignaturePolicyImplied', namespaces=NS_MAP)
        if implied is not None:
            return
        data = self._query_signature_policy_identifer_data(node)
        value = self.policy
        value = self.set_transforms(data['Transforms'], value, False)
        hash_calc = hashlib.new(
            TransformUsageDigestMethod[data['DigestMethodAlgorithm']])
        hash_calc.update(value)
        digest_val = hash_calc.digest()
        assert data['DigestValue'].encode() == b64encode(digest_val)