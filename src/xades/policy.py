# -*- coding: utf-8 -*-
# © 2017 Creu Blanca
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).

from base64 import b64decode, b64encode
import hashlib

from xades.ns import EtsiNS
from xades.constants import NS_MAP, MAP_HASHLIB
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_der_x509_certificate
from xades.utils import rdns_to_map, dict_compare
from xmlsig.constants import TransformUsageDigestMethod
from xmlsig.ns import DSigNs
from xmlsig.utils import create_node, USING_PYTHON2, get_rdns_name

if USING_PYTHON2:
    import urllib
else:
    import urllib.request as urllib


class Policy(object):
    """"
    Policy class created in order to define different policies
    """

    hash_method = None

    def sign(self, signature):
        return

    def validate(self, signature):
        return

    def calculate_policy_node(self, node, sign=False):
        if sign:
            return create_node('SignaturePolicyImplied', node, EtsiNS)
        return node.find('etsi:SignaturePolicyImplied', namespaces=NS_MAP)

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


class PolicyId(Policy):
    id = None
    name = None

    def set_transforms(self, node, value, sign=False):
        """
        Transformations of the policy if required. Modifies node and returns
        transformed value
        :param node: Policy node
        :param value: Original value
        :return: str
        """
        return value

    def calculate_policy_node(self, node, sign=False):
        if sign:
            policy_id = create_node('SignaturePolicyId', node, EtsiNS)
            identifier = create_node('SigPolicyId', policy_id, EtsiNS)
            create_node('Identifier', identifier, EtsiNS).text = self.id
            create_node('Description', identifier, EtsiNS).text = self.name
            remote = self.id
        else:
            policy_id = node.find('etsi:SignaturePolicyId', namespaces=NS_MAP)
            identifier = policy_id.find('etsi:SigPolicyId',  namespaces=NS_MAP)
            remote = identifier.find('etsi:Identifier', namespaces=NS_MAP).text
        value = urllib.urlopen(remote).read()
        value = self.set_transforms(policy_id, value, sign)
        if sign:
            hash_method = self.hash_method
            digest = create_node('SigPolicyHash', policy_id, EtsiNS)
            digest_method = create_node('DigestMethod', digest, DSigNs)
            digest_method.set('Algorithm', self.hash_method)
            digest_value = create_node('DigestValue', digest, DSigNs)
        else:
            hash_method = policy_id.find(
                'etsi:SigPolicyHash/ds:DigestMethod', namespaces=NS_MAP
            ).get('Algorithm')
            digest_value  = policy_id.find(
                'etsi:SigPolicyHash/ds:DigestValue', namespaces=NS_MAP
            )
        hash_calc = hashlib.new(TransformUsageDigestMethod[hash_method])
        hash_calc.update(value)
        digest_val = hash_calc.digest()
        if sign:
            digest_value.text = b64encode(digest_val)
        assert digest_value.text.encode() == b64encode(digest_val)
        return policy_id

