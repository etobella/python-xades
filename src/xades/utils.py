# -*- coding: utf-8 -*-
# © 2017 Creu Blanca
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).


def dict_compare(d1, d2):
    assert len(d1) == len(d2)
    d1_keys = set(d1.keys())
    d2_keys = set(d2.keys())
    intersect_keys = d1_keys.intersection(d2_keys)
    assert len(intersect_keys) == len(d1)
    for key in d1_keys:
        assert d1[key] == d2[key]


def rdns_to_map(data):
    return {x.split('=')[0]: x.split('=')[1] for x in data.split(',') if x}
