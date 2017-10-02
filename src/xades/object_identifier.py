from xmlsig.utils import create_node
from .ns import EtsiNS


class ObjectIdentifier(object):
    def __init__(self, identifier, description=None,
                 references=[]):
        self.identifier = identifier
        self.description = description
        self.references = references

    def to_xml(self, node):
        create_node('Identifier', node, EtsiNS).text = self.identifier
        if self.description is not None:
            create_node('Description', node, EtsiNS).text = self.description
        if len(self.references) > 0:
            documentation = create_node(
                'DocumentationReferences', node, EtsiNS
            )
            for reference in self.references:
                create_node(
                    'DocumentationReference', documentation, EtsiNS
                ).text = reference


