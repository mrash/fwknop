#!/usr/bin/python
##############################################################################
#
# File:    setup.py
#
# Purpose: Driver script for the fko module.
#
# Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
# Copyright (C) 2009-2014 fwknop developers and contributors. For a full
# list of contributors, see the file 'CREDITS'.
#
# License (GNU General Public License):
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
# USA
#
##############################################################################
#
from distutils.core import setup, Extension

# The fko extension module.
#
fko_ext = Extension(
    '_fko',
    define_macros = [('MAJOR_VERSION', '1'), ('MINOR_VERSION', '5')],
                    include_dirs = ['../lib/'],
                    library_dirs = ['../lib/.libs'],
                    libraries = ['fko'],
                    sources = ['fkomodule.c']
)

setup (
    name = 'fko',
    version = '1.5',
    description = 'Wrapper for Fwknop library (libfko)',
    author = 'Damien S. Stuart',
    author_email = 'dstuart@dstuart.org',
    license = 'GPL2',
    long_description = '''
Python module that wraps the fwknop library to provide the ability to
generate, decode, parse, and process SPA formatted messages.
''',
    ext_modules = [fko_ext],
    py_modules = ['fko']
)

###EOF###
