from cryptography.hazmat.primitives import hashes

from xmlsig import constants
from .ns import EtsiNS

NS_MAP = constants.NS_MAP
NS_MAP['etsi'] = EtsiNS

MAP_HASHLIB = {
    constants.TransformMd5: hashes.MD5,
    constants.TransformSha1: hashes.SHA1,
    constants.TransformSha224: hashes.SHA224,
    constants.TransformSha256: hashes.SHA256,
    constants.TransformSha384: hashes.SHA384,
    constants.TransformSha512: hashes.SHA512,
    constants.TransformRipemd160: hashes.RIPEMD160,
}
