#!/usr/bin/env python

import os

from setuptools import setup

package_name = "ROPGadget"
package_dir  = "ropgadget"
package_description = "This tool lets you search your gadgets on your binaries to facilitate your ROP exploitation."
long_description = """
ROPgadget supports ELF, PE and Mach-O format on x86, x64, ARM, ARM64, PowerPC, SPARC and MIPS architectures.
http://www.shell-storm.org/project/ROPgadget/
""".strip()


def fullsplit(path, result=None):
    """
    Split a pathname into components (the opposite of os.path.join) in a
    platform-neutral way.
    """
    if result is None:
        result = []
    head, tail = os.path.split(path)
    if head == '':
        return [tail] + result
    if head == path:
        return result
    return fullsplit(head, [tail] + result)


# Compile the list of packages available, because distutils doesn't have
# an easy way to do this.
packages, data_files = [], []
root_dir = os.path.dirname(__file__)
if root_dir != '':
    os.chdir(root_dir)

for dirpath, dirnames, filenames in os.walk(package_dir):
    # Ignore dirnames that start with '.'
    for i, dirname in enumerate(dirnames):
        if dirname.startswith('.'):
            del dirnames[i]
    if '__init__.py' in filenames:
        packages.append('.'.join(fullsplit(dirpath)))
    elif filenames:
        data_files.append([dirpath, [os.path.join(dirpath, f) for f in filenames]])

version = "6.5"

setup(
    name             = package_name,
    version          = version,
    description      = package_description,
    long_description = long_description,
    packages         = packages,
    license          = "BSD",
    author           = "Jonathan Salwan",
    author_email     = "jonathan.salwan@gmail.com",
    url              = "https://github.com/JonathanSalwan/ROPgadget",
    scripts          = ['scripts/ROPgadget'],
    install_requires = ['capstone'],
    classifiers      = [
        'Topic :: Security',
        'Environment :: Console',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Intended Audience :: Developers',
    ],
)
