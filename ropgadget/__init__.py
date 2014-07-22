#!/usr/bin/env python2
## -*- coding: utf-8 -*-
##
##  Jonathan Salwan - 2014-05-12 - ROPgadget tool
##
##  http://twitter.com/JonathanSalwan
##  http://shell-storm.org/project/ROPgadget/
##
##  This program is free software: you can redistribute it and/or modify
##  it under the terms of the GNU General Public License as published by
##  the Free Software  Foundation, either  version 3 of  the License, or
##  (at your option) any later version.

import args, binary, core, gadgets, options, rgutils, updateAlert, version
import loaders, ropchain

def main():
    import sys
    from   args import Args
    from   core import Core
    sys.exit(Core(Args().getArgs()).analyze())
