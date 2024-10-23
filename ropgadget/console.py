
# Built-in imports
import sys

# Local library imports
import ropgadget.src.gadgets
import ropgadget.loaders
import ropgadget.src.options
import ropgadget.src.rgutils
import ropgadget.ropchain
import ropgadget.updateAlert
import ropgadget.version

from ropgadget.args import Args
from ropgadget.src.core import Core


def run():
    try:
        args = Args()
    except ValueError as error:
        print(error)
        sys.exit(-1)

    sys.exit(0 if Core(args.getArgs()).analyze() else 1)
