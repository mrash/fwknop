#!/usr/bin/python
##############################################################################
#
# File:    setup.py
#
# Author:  Damien S. Stuart <dstuart@dstuart.org>
#
# Purpose: Driver script for the fko module.
#
##############################################################################
#
from distutils.core import setup, Extension

# The fko extension module.
#
fko_ext = Extension(
    '_fko',
    define_macros = [('MAJOR_VERSION', '1'), ('MINOR_VERSION', '0')],
                    libraries = ['fko'],
                    sources = ['fkomodule.c']
)

setup (
    name = 'fko',
    version = '1.0',
    description = 'Wrapper for Fwknop library (libfko)',
    author = 'Damien S. Stuart',
    author_email = 'dstuart@dstuart.org',
    license = 'GPL',
    long_description = '''
Python module that wraps the fwknop library to provide the ability to
generate, decode, parse, and process SPA formatted messages.
''',
    ext_modules = [fko_ext],
    py_modules = ['fko']
)

###EOF###
