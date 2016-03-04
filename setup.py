# -*- coding: utf-8 -*-
from setuptools import setup, find_packages
import os
import glob
import sys

#VERSION="2.1dev4"
VERSION="2.11dev0"

install_requires = []
# For python 2.6 we need additional dependency importlib
try:
    import importlib
except ImportError:
    install_requires.append('importlib')

setup(
    name='privacyidea_pam',
    version=VERSION,
    author='privacyidea.org',
    license='AGPLv3',
    author_email='cornelius@privacyidea.org',
    url='http://www.privacyidea.org',
    keywords='OTP, two factor authentication, management, security',
    py_modules=['privacyidea_pam'],
    install_requires=install_requires,
    classifiers=["Framework :: Flask",
                 "License :: OSI Approved :: "
                 "GNU Affero General Public License v3",
                 "Programming Language :: Python",
                 "Development Status :: 5 - Production/Stable",
                 "Topic :: Internet",
                 "Topic :: Security",
                 "Topic :: System ::"
                 " Systems Administration :: Authentication/Directory"
                 ],
    #message_extractors={'privacyidea': [
    #        ('**.py', 'python', None),
    #        ('static/**.html', 'html', {'input_encoding': 'utf-8'})]},
    zip_safe=False
)
