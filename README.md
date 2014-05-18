ROPgadget Tool
================

This tool lets you search your gadgets on your binaries to facilitate your ROP exploitation.
ROPgadget supports ELF/PE/Mach-O format on x86, x64, ARM, ARM64, PowerPC, SPARC and MIPS
architectures. Since the version 5, ROPgadget has a new core which is written in Python
using Capstone disassembly framework for the gadgets search engine - The older version can
be found in the Archives directory but it will not be maintained.

Install
-------

To install on nix systems, run:

    $ ./install.sh

Capstone supports multi-platforms (windows, ios, android, cygwin...). For the cross-compilation,
please refer to COMPILE.txt in the Capstone repository root.

Usage
-----

    usage: ROPgadget.py [-h] [-v] [-c] [--binary <binary>] [--opcode <opcodes>]
                        [--string <string>] [--memstr <string>] [--depth <nbyte>]
                        [--only <key>] [--filter <key>] [--range <start-end>]
                        [--badbytes <byte>] [--rawArch <arch>] [--rawMode <mode>]
                        [--offset <hexaddr>] [--ropchain] [--thumb] [--console]
                        [--norop] [--nojop] [--nosys]

    optional arguments:
      -h, --help           show this help message and exit
      -v, --version        Display the ROPgadget's version
      -c, --checkUpdate    Checks if a new version is available
      --binary <binary>    Specify a binary filename to analyze
      --opcode <opcodes>   Searh opcode in executable segment
      --string <string>    Search string in readable segment
      --memstr <string>    Search each byte in all readable segment
      --depth <nbyte>      Depth for search engine (default 10)
      --only <key>         Only show specific instructions
      --filter <key>       Suppress specific instructions
      --range <start-end>  Search between two addresses (0x...-0x...)
      --badbytes <byte>    Rejects specific bytes in the gadget's address
      --rawArch <arch>     Specify an arch for a raw file
      --rawMode <mode>     Specify a mode for a raw file
      --offset <hexaddr>   Specify an offset for gadget addresses
      --ropchain           Enable the ROP chain generation
      --thumb              Use the thumb mode for the search engine (ARM only)
      --console            Use an interactive console for search engine
      --norop              Disable ROP search engine
      --nojop              Disable JOP search engine
      --nosys              Disable SYS search engine

    console commands:
      badbytes             Rejects specific bytes in the gadget's address
      count                Display the number of gadgets loaded
      depth                Set the depth search engine
      display              Display all gadgets
      help                 Display the help
      load                 Load all gadgets
      loaddb               Loads gadgets from an sqlite database
      quit                 Quit the console mode
      save2db              Saves the loaded gadgets to an sqlite database
      search               Search specific keywords or not


How can I contribute ?
----------------------

- Use Z3 to solve the ROP chain
- Add system gadgets for PPC, Sparc, ARM64 (Gadgets.addSYSGadgets())
- Manage big endian in Mach-O format like the ELF classe.
- Everything you think is cool :)

Bugs/Patches/Contact
--------------------

Please report bugs, submit pull requests, etc. on github at https://github.com/JonathanSalwan/ROPgadget
The offical page is on shell-storm.org at http://shell-storm.org/project/ROPgadget/

License
-------

See COPYING and the license header on all source files. For the files in the dependencies/ there are
individual licenses in each folder.</p>


Screenshots
-----------

<img src="http://shell-storm.org/project/ROPgadget/x64.png" alt="x64"></img>

<img src="http://shell-storm.org/project/ROPgadget/arm.png" alt="ARM"></img>

<img src="http://shell-storm.org/project/ROPgadget/sparc.png" alt="Sparc"></img>

<img src="http://shell-storm.org/project/ROPgadget/mips.png" alt="MIPS"></img>

<img src="http://shell-storm.org/project/ROPgadget/ppc.png" alt="PowerPC"></img>

<img src="http://shell-storm.org/project/ROPgadget/ropchain.png" alt="ROP chain"></img>

