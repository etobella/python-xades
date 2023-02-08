# © 2017 Creu Blanca
# License LGPL-3.0 or later (http://www.gnu.org/licenses/lgpl.html).

from uuid import uuid4

from .constants import ID_ATTR


def dict_compare(d1, d2):
    assert len(d1) == len(d2)
    d1_keys = set(d1.keys())
    d2_keys = set(d2.keys())
    intersect_keys = d1_keys.intersection(d2_keys)
    assert len(intersect_keys) == len(d1)
    for key in d1_keys:
        assert d1[key] == d2[key]


def rdns_to_map(data):
    return {
        x.split("=")[0].strip(): x.split("=")[1].strip() for x in data.split(",") if x
    }


def get_unique_id():
    return "id-{}".format(uuid4())


def ensure_id(node):
    """Ensure given node has a wsu:Id attribute; add unique one if not.

    Return found/created attribute value.

    """
    assert node is not None
    id_val = node.get(ID_ATTR)
    if not id_val:
        id_val = get_unique_id()
        node.set(ID_ATTR, id_val)
    return id_val
