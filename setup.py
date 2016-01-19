#!/usr/bin/env python
# -*- coding: utf-8 -*-


try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

requirements = [
    # TODO: put package requirements here
]

test_requirements = [
    "pysha3",
    "pyblake2",
    "pytest"
    # TODO: put package test requirements here
]

setup(
    name='multihash',
    version='0.0.9',
    description="Multihash implementation in Python with both high and low level APIs.",
    long_description=readme + '\n\n' + history,
    author="Javier Candeira",
    author_email='javier@candeira.com',
    url='https://github.com/candeira/multihash',
    packages=[
        'multihash',
    ],
    package_dir={'multihash':
                 'multihash'},
    include_package_data=True,
    install_requires=requirements,
    license="MIT",
    zip_safe=False,
    keywords='multihash',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
    ],
    test_suite='tests',
    tests_require=test_requirements
)
