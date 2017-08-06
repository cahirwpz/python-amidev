#!/usr/bin/env python3.5
# -*- coding: utf-8 -*-

from __future__ import print_function

import os
import sys

from setuptools import setup, find_packages

scripts = {
  'console_scripts' : [
    'dumphunk = amidev.dumphunk:main',
    'dumpaout = amidev.dumpaout:main',
    'dumpar = amidev.dumpar:main',
    'uaedbg = amidev.uaedbg:main',
  ]
}

setup(
    name = 'amidev',
    description='Various tools useful for AmigaOS/m68k development',
    version = '0.1',
    maintainer = "Krystian Bacławski",
    maintainer_email = "krystian.baclawski@gmail.com",
    url = "http://github.com/github/amigaos-dev-toolkit",
    classifiers = [
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Topic :: System :: Emulators",
    ],
    license = "License :: OSI Approved :: BSD License",
    packages = find_packages(),
    zip_safe = False,
    entry_points = scripts,
    include_package_data=True
)

