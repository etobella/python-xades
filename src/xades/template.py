from lxml import etree

from xmlsig.constants import DSigNs
from xmlsig.utils import create_node
from .constants import NS_MAP, EtsiNS, ID_ATTR


def create_qualifying_properties(node, name=None, etsi='etsi'):
    obj_node = create_node('Object', node, DSigNs)
    qualifying = etree.SubElement(
        obj_node,
        etree.QName(EtsiNS, 'QualifyingProperties'),
        nsmap={etsi: EtsiNS}
    )
    qualifying.set('Target', '#' + node.get(ID_ATTR))
    if name is not None:
        qualifying.set(ID_ATTR, name)
    return qualifying


def create_signed_properties(node, name=None, datetime=None):
    properties = create_node('SignedProperties', node, EtsiNS)
    if name is not None:
        properties.set(ID_ATTR, name)
    signature_properties = create_node(
        'SignedSignatureProperties', properties, EtsiNS
    )
    signing_time = create_node('SigningTime', signature_properties, EtsiNS)
    if datetime is not None:
        signing_time.text = datetime.isoformat()
    create_node('SigningCertificate', signature_properties, EtsiNS)
    create_node('SignaturePolicyIdentifier', signature_properties, EtsiNS)
    return properties


def add_production_place(
        node, city=None, state=None, postal_code=None, country=None):
    signature_properties = node.find(
        'etsi:SignedSignatureProperties', namespaces=NS_MAP
    )
    production_place = signature_properties.find(
        'etsi:SignatureProductionPlace', namespaces=NS_MAP
    )
    if production_place is None:
        production_place = create_node(
            'SignatureProductionPlace', ns=EtsiNS
        )
        signature_properties.insert(3, production_place)
    for child in production_place.getchildren():
        production_place.remove(child)
    if city is not None:
        create_node('City', production_place, EtsiNS).text = city
    if state is not None:
        create_node('StateOrProvince', production_place, EtsiNS).text = state
    if postal_code is not None:
        create_node('PostalCode', production_place, EtsiNS).text = postal_code
    if country is not None:
        create_node('CountryName', production_place, EtsiNS).text = country


def add_claimed_role(node, role):
    signature_properties = node.find(
        'etsi:SignedSignatureProperties', namespaces=NS_MAP
    )
    signer_role = signature_properties.find(
        'etsi:SignerRole', namespaces=NS_MAP
    )
    if signer_role is None:
        signer_role = create_node(
            'SignerRole', signature_properties, ns=EtsiNS
        )
    claimed_roles = signer_role.find(
        'etsi:ClaimedRoles', namespaces=NS_MAP
    )
    if claimed_roles is None:
        claimed_roles = create_node(
            'ClaimedRoles', ns=EtsiNS
        )
        signer_role.insert(0, claimed_roles)
    claimed_role = create_node('ClaimedRole', claimed_roles, EtsiNS)
    claimed_role.text = role
    return claimed_role
