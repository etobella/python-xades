====================================
XAdES: Python native XAdES Signature
====================================

A python native library that signs and verifies XAdES signatures

Highlights:
 * Build on top of lxml, cryptography and xmlsig


.. start-no-pypi

Status
------

.. image:: https://travis-ci.org/etobella/python-xades.svg?branch=master
    :target: https://travis-ci.org/etobella/python-xades

.. image:: http://codecov.io/github/etobella/python-xades/coverage.svg?branch=master
    :target: http://codecov.io/github/etobella/python-xades?branch=master

.. image:: https://img.shields.io/pypi/v/xades.svg
    :target: https://pypi.python.org/pypi/xades/

.. end-no-pypi

Installation
------------

.. code-block:: bash

    pip install xades

Usage
=====

.. code::

  import xades
  import xmlsig

  sign = xmlsig.template.create(c14n_method=xmlsig.constants.TransformExclC14N, sign_method=xmlsig.constants.TransformRsaSha1)
  ref = xmlsig.template.add_reference(sign, xmlsig.constants.TransformSha1)
  xmlsig.template.add_transform(ref, xmlsig.constants.TransformEnveloped)
  qualifying = template.create_qualifying_properties(signature)
  props = template.create_signed_properties(qualifying)
  policy = xades.policy.GenericPolicyId(
            policy_id,
            policy_name,
            xmlsig.constants.TransformSha1)
  ctx = xades.XAdESContext(policy)



To have more examples, look at the source code of the testings

Functionality
=============

XAdES EPES is implemented.
More functionalities are still on work.

License
=======

This library is published under AGPL-3 license.

Contributors
============

* Enric Tobella <etobella@creublanca.es>
