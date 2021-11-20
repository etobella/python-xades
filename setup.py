import pathlib

from pkg_resources import parse_requirements
from setuptools import find_packages, setup

with pathlib.Path("requirements.txt").open() as requirements_txt:
    install_requires = [
        str(requirement) for requirement in parse_requirements(requirements_txt)
    ]
with pathlib.Path("test-requirements.txt").open() as requirements_txt:
    test_requires = [
        str(requirement) for requirement in parse_requirements(requirements_txt)
    ]


setup(
    name="xades",
    version="0.2.2",
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
    license="AGPL-3",
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
