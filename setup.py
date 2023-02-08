from setuptools import find_packages, setup

install_requires = [
    "xmlsig",
    "pytz",
]
test_requires = ["xmlsig[test]"]


setup(
    name="xades",
    version="1.0.0",
    description="XaDES XML signature",
    long_description="XaDES XML Signature created with cryptography and lxml",
    author="Enric Tobella Alomar",
    author_email="etobella@creublanca.es",
    url="http://github.com/etobella/python-xades",
    install_requires=install_requires,
    tests_require=test_requires,
    extras_require={"test": test_requires},
    entry_points={},
    package_dir={"": "src"},
    packages=find_packages("src"),
    include_package_data=True,
    license="LGPL-3",
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
    ],
    zip_safe=False,
)
