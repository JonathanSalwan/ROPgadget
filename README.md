ROPgadget Tool
================

This tool lets you search your gadgets on your binaries to facilitate your ROP exploitation.
ROPgadget supports ELF/PE/Mach-O format on x86, x64, ARM, ARM64, PowerPC, SPARC and MIPS
architectures. Since the version 5, ROPgadget has a new core which is written in Python
using Capstone disassembly framework for the gadgets search engine - The older version can
be found in the Archives directory but it will not be maintained.

Install
-------

If you want to use ROPgadget, you have to install [Capstone](http://www.capstone-engine.org/) first.

For the Capstone's installation on nix machine:

    $ sudo pip install capstone

Capstone supports multi-platforms (windows, ios, android, cygwin...). For the cross-compilation,
please refer to the https://github.com/aquynh/capstone/blob/master/COMPILE.TXT file.

After Capstone is installed, ROPgadget can be used as a standalone tool:

    $ ROPgadget.py

Or installed into the Python site-packages library, and executed from $PATH.

    $ python setup.py install
    $ ROPgadget

Or installed from PyPi

    $ pip install ropgadget
    $ ROPgadget

Usage
-----

    usage: ROPgadget.py [-h] [-v] [-c] [--binary <binary>] [--opcode <opcodes>]
                        [--string <string>] [--memstr <string>] [--depth <nbyte>]
                        [--only <key>] [--filter <key>] [--range <start-end>]
                        [--badbytes <byte>] [--rawArch <arch>] [--rawMode <mode>]
                        [--rawEndian <endian>] [--re <re>] [--offset <hexaddr>]
                        [--ropchain] [--thumb] [--console] [--norop] [--nojop]
                        [--callPreceded] [--nosys] [--multibr] [--all] [--noinstr]
                        [--dump] [--silent] [--align ALIGN]

    optional arguments:
        -h, --help           show this help message and exit
        -v, --version        Display the ROPgadget's version
        -c, --checkUpdate    Checks if a new version is available
        --binary <binary>    Specify a binary filename to analyze
        --opcode <opcodes>   Search opcode in executable segment
        --string <string>    Search string in readable segment
        --memstr <string>    Search each byte in all readable segment
        --depth <nbyte>      Depth for search engine (default 10)
        --only <key>         Only show specific instructions
        --filter <key>       Suppress specific mnemonics
        --range <start-end>  Search between two addresses (0x...-0x...)
        --badbytes <byte>    Rejects specific bytes in the gadget's address
        --rawArch <arch>     Specify an arch for a raw file
        --rawMode <mode>     Specify a mode for a raw file
        --rawEndian <endian> Specify an endianness for a raw file
        --re <re>            Regular expression
        --offset <hexaddr>   Specify an offset for gadget addresses
        --ropchain           Enable the ROP chain generation
        --thumb              Use the thumb mode for the search engine (ARM only)
        --console            Use an interactive console for search engine
        --norop              Disable ROP search engine
        --nojop              Disable JOP search engine
        --callPreceded       Only show gadgets which are call-preceded
        --nosys              Disable SYS search engine
        --multibr            Enable multiple branch gadgets
        --all                Disables the removal of duplicate gadgets
        --noinstr            Disable the gadget instructions console printing
        --dump               Outputs the gadget bytes
        --silent             Disables printing of gadgets during analysis
        --align ALIGN        Align gadgets addresses (in bytes)
        --mipsrop <rtype>    MIPS useful gadgets finder
                             stackfinder|system|tails|lia0|registers

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

