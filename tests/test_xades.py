import unittest
from os import path

import xmlsig
from base import BASE_DIR, parse_xml
from xades import XAdESContext
from OpenSSL import crypto
from lxml import etree


class TestXadesSignature(unittest.TestCase):
    def test_verify(self):
        root = parse_xml('data/sample.xml')
        sign = root.xpath(
            '//ds:Signature', namespaces={'ds': xmlsig.constants.DSigNs}
        )[0]
        ctx = XAdESContext()
        ctx.verify(sign)

    def test_sign(self):
        root = parse_xml('data/unsigned-sample.xml')
        sign = root.xpath(
            '//ds:Signature', namespaces={'ds': xmlsig.constants.DSigNs}
        )[0]
        ctx = XAdESContext()
        with open(path.join(BASE_DIR, "data/keyStore.p12"), "rb") as key_file:
            ctx.load_pcks12(crypto.load_pkcs12(key_file.read()))
        ctx.sign(sign)

