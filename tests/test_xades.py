import unittest
from os import path

import xmlsig
from base import BASE_DIR, parse_xml
from xades import XAdESContext, PolicyId, template
from OpenSSL import crypto
from lxml import etree


class TestXadesSignature(unittest.TestCase):
    def test_verify(self):
        root = parse_xml('data/sample.xml')
        sign = root.xpath(
            '//ds:Signature', namespaces={'ds': xmlsig.constants.DSigNs}
        )[0]
        ctx = XAdESContext(PolicyId())
        ctx.verify(sign)

    def test_sign(self):
        root = parse_xml('data/unsigned-sample.xml')
        sign = root.xpath(
            '//ds:Signature', namespaces={'ds': xmlsig.constants.DSigNs}
        )[0]
        policy = PolicyId()
        policy.id = 'http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf'
        policy.name = u"Politica de Firma FacturaE v3.1"
        policy.hash_method = xmlsig.constants.TransformSha1
        ctx = XAdESContext(policy)
        with open(path.join(BASE_DIR, "data/keyStore.p12"), "rb") as key_file:
            ctx.load_pkcs12(crypto.load_pkcs12(key_file.read()))
        ctx.sign(sign)
        ctx.verify(sign)

    def test_create(self):
        root = parse_xml('data/free-sample.xml')
        signature = xmlsig.template.create(
            xmlsig.constants.TransformInclC14N,
            xmlsig.constants.TransformRsaSha1,
            "Signature"
        )
        ref = xmlsig.template.add_reference(
            signature, xmlsig.constants.TransformSha1, uri=""
        )
        xmlsig.template.add_transform(ref, xmlsig.constants.TransformEnveloped)
        xmlsig.template.add_reference(
            signature, xmlsig.constants.TransformSha1, uri="#KI"
        )
        xmlsig.template.add_reference(
            signature, xmlsig.constants.TransformSha1, uri="#SIGN"
        )
        ki = xmlsig.template.ensure_key_info(signature, name='KI')
        data = xmlsig.template.add_x509_data(ki)
        xmlsig.template.x509_data_add_certificate(data)
        xmlsig.template.add_key_value(ki)
        qualifying = template.create_qualifying_properties(signature)
        props = template.create_signed_properties(qualifying, name="SIGN")
        template.add_claimed_role(props, "Supp2")
        template.add_production_place(props, 'Madrid')
        template.add_production_place(props, 'BCN', 'BCN', '08000', 'ES')
        template.add_claimed_role(props, "Supp")
        policy = PolicyId()
        policy.id = 'http://www.facturae.es/politica_de_firma_formato_' \
                    'facturae/politica_de_firma_formato_facturae_v3_1.pdf'
        policy.name = u"Politica de Firma FacturaE v3.1"
        policy.hash_method = xmlsig.constants.TransformSha1
        root.append(signature)
        ctx = XAdESContext(policy)
        with open(path.join(BASE_DIR, "data/keyStore.p12"), "rb") as key_file:
            ctx.load_pkcs12(crypto.load_pkcs12(key_file.read()))
        ctx.sign(signature)
        ctx.verify(signature)

