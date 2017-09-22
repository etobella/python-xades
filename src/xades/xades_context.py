from base64 import b64decode, b64encode

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.primitives.serialization import Encoding

from xmlsig import SignatureContext, utils
from .constants import NS_MAP, MAP_HASHLIB
from .utils import rdns_to_map, dict_compare


class XAdESContext(SignatureContext):
    def sign(self, node):
        res = super(XAdESContext, self).sign(node)
        return res

    def verify(self, node):
        signed_properties = node.find(
            "ds:Object/etsi:QualifyingProperties["
            "@Target='#{}']/etsi:SignedProperties".format(
                node.get('Id')),
            namespaces=NS_MAP)
        assert signed_properties is not None
        self.verify_signed_properties(signed_properties, node)
        unsigned_properties = node.find(
            "ds:Object/etsi:QualifyingProperties["
            "@Target='#{}']/etsi:UnSignedProperties".format(
                node.get('Id')),
            namespaces=NS_MAP)
        if unsigned_properties is not None:
            self.verify_unsigned_properties(signed_properties, node)
        res = super(XAdESContext, self).verify(node)
        return res

    def verify_signed_properties(self, signed_properties, node):
        signature_properties = signed_properties.find(
            'etsi:SignedSignatureProperties', namespaces=NS_MAP
        )
        assert signature_properties is not None
        self.verify_signature_properties(signature_properties, node)
        data_object_properties = signed_properties.find(
            'etsi:SignedDataObjectProperties', namespaces=NS_MAP
        )
        if signature_properties is None:
            self.verify_data_object_properties(data_object_properties, node)
        return

    def verify_signature_properties(self, signature_properties, node):
        signing_time = signature_properties.find(
            'etsi:SigningTime', namespaces=NS_MAP
        )
        assert signing_time is not None
        # TODO: Verificate time format
        certificate_list = signature_properties.find(
            'etsi:SigningCertificate', namespaces=NS_MAP
        )
        assert certificate_list is not None
        self.verify_certificate(certificate_list, node)
        policy = signature_properties.find(
            'etsi:SignaturePolicyIdentifier', namespaces=NS_MAP
        )
        assert policy is not None
        policy_id = policy.find(
            'etsi:SignaturePolicyId', namespaces=NS_MAP
        )
        if policy_id is not None:
            return
        else:
            policy_implied = policy.find(
                'etsi:SignaturePolicyImplied', namespaces=NS_MAP
            )
            assert policy_implied is not None
            # TODO: Verify Signature Policy
        return

    def verify_certificate(self, certificate_list, node):
        certs = certificate_list.findall('etsi:Cert', namespaces=NS_MAP)
        x509 = node.find('ds:KeyInfo/ds:X509Data', namespaces=NS_MAP)
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
                    'etsi:IssuerSerial/ds:X509SerialNumber', namespaces=NS_MAP
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
                rdns_to_map(utils.get_rdns_name(parsed_x509.issuer.rdns)),
                rdns_to_map(certificate.find(
                    'etsi:IssuerSerial/ds:X509IssuerName', namespaces=NS_MAP
                ).text)
            )
            digest = certificate.find(
                'etsi:CertDigest', namespaces=NS_MAP
            )
            assert b64encode(parsed_x509.fingerprint(MAP_HASHLIB[digest.find(
                'ds:DigestMethod', namespaces=NS_MAP
            ).get('Algorithm')]())) == digest.find(
                'ds:DigestValue', namespaces=NS_MAP).text

    def verify_data_object_properties(self, data_object_properties, node):
        return

    def verify_unsigned_properties(self, unsigned_properties, node):
        return
