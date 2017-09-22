===================================
XmlSIG: Python native XML Signature
===================================

A python native library that signs and verifies xml signatures

Highlights:
 * Build on top of lxml and cryptography


.. start-no-pypi

Status
------

.. image:: https://travis-ci.org/etobella/python-xmlsig.svg?branch=master
    :target: https://travis-ci.org/etobella/python-xmlsig

.. image:: http://codecov.io/github/etobella/python-xmlsig/coverage.svg?branch=master
    :target: http://codecov.io/github/etobella/python-xmlsig?branch=master

.. image:: https://img.shields.io/pypi/v/xmlsig.svg
    :target: https://pypi.python.org/pypi/xmlsig/

.. end-no-pypi

Installation
------------

.. code-block:: bash

    pip install xmlsig

Usage
=====

.. code::

  import xmlsig

  sign = xmlsig.template.create(c14n_method=xmlsig.constants.TransformExclC14N, sign_method=xmlsig.constants.TransformRsaSha1)
  ref = xmlsig.template.add_reference(sign, xmlsig.constants.TransformSha1)
  xmlsig.template.add_transform(ref, xmlsig.constants.TransformEnveloped)

  ctx = xmlsig.SignatureContext()



To have more examples, look at the source code of the testings

Functionality
=============

Signature is only valid using RSA and HMAC validation.
ECDSA and DSA is still being implemented

License
=======

This library is published under the BSD license.

Contributors
============

* Enric Tobella <etobella@creublanca.es>
