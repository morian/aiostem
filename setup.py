#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import io
import os
import setuptools


verdata = {}
with io.open('aiostem/version.py') as fp:
    exec(fp.read(), verdata)
version = verdata['version']

with io.open('README.md', 'r') as fp:
    description = fp.read()

setuptools.setup(
    name             = 'aiostem',
    version          = version,
    author           = 'Romain Bezut',
    author_email     = 'morian@xdec.net',
    description      = 'Asynchronous Tor controller library for asyncio and Python',
    license          = 'MIT',
    packages         = setuptools.find_packages(),
    long_description = description,
    long_description_content_type = 'text/markdown',
    install_requires = [
        'aiofiles',
    ],
    classifiers      = [
        "Operating System :: POSIX :: Linux",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
)
