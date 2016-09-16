## -*- coding: utf-8 -*-
##
##  Jonathan Salwan - 2014-05-12 - ROPgadget tool
##
##  http://twitter.com/JonathanSalwan
##  http://shell-storm.org/project/ROPgadget/
##

import ropgadget.args
import ropgadget.binary
import ropgadget.core
import ropgadget.gadgets
import ropgadget.options
import ropgadget.rgutils
import ropgadget.updateAlert
import ropgadget.version
import ropgadget.loaders
import ropgadget.ropchain

def main():
    import sys
    from   ropgadget.args import Args
    from   ropgadget.core import Core
    sys.exit(Core(Args().getArgs()).analyze())
