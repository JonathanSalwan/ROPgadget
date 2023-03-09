ROPgadget Tool
==============

This tool lets you search your gadgets on your binaries to facilitate your ROP
exploitation. ROPgadget supports ELF/PE/Mach-O/Raw formats on x86, x64, ARM,
ARM64, PowerPC, SPARC, MIPS, RISC-V 64, and RISC-V Compressed architectures.

Install
-------

The easiest way is installing ROPgadget from PyPi:

    $ sudo apt install python3-pip
    $ sudo -H python3 -m pip install ROPgadget
    $ ROPgadget --help

Alternatively you can install ROPgadget from source.
You have to install [Capstone](http://www.capstone-engine.org/) first.

For the Capstone's installation on nix machine:

    $ sudo apt install python3-pip
    $ sudo -H python3 -m pip install capstone

Capstone supports multi-platforms (windows, ios, android, cygwin...). For the cross-compilation,
please refer to the https://github.com/capstone-engine/capstone/blob/master/COMPILE.TXT file.

After Capstone is installed, ROPgadget can be used as a standalone tool:

    $ python3 ROPgadget.py --help

Or installed into the Python site-packages library, and executed from $PATH.

    $ sudo -H python3 setup.py install
    $ ROPgadget --help

Usage
-----

    usage: ROPgadget.py [-h] [-v] [-c] [--binary <binary>] [--opcode <opcodes>]
                        [--string <string>] [--memstr <string>] [--depth <nbyte>]
                        [--only <key>] [--filter <key>] [--range <start-end>]
                        [--badbytes <byte>] [--rawArch <arch>] [--rawMode <mode>]
                        [--rawEndian <endian>] [--re <re>] [--offset <hexaddr>]
                        [--ropchain] [--thumb] [--console] [--norop] [--nojop]
                        [--callPreceded] [--nosys] [--multibr] [--all] [--noinstr]
                        [--dump] [--silent] [--align ALIGN] [--mipsrop <rtype>]

    description:
      ROPgadget lets you search your gadgets on a binary. It supports several
      file formats and architectures and uses the Capstone disassembler for
      the search engine.

    formats supported:
      - ELF
      - PE
      - Mach-O
      - Raw

    architectures supported:
      - x86
      - x86-64
      - ARM
      - ARM64
      - MIPS
      - PowerPC
      - Sparc
      - RISC-V 64
      - RISC-V Compressed

    optional arguments:
      -h, --help            show this help message and exit
      -v, --version         Display the ROPgadget's version
      -c, --checkUpdate     Checks if a new version is available
      --binary <binary>     Specify a binary filename to analyze
      --opcode <opcodes>    Search opcode in executable segment
      --string <string>     Search string in readable segment
      --memstr <string>     Search each byte in all readable segment
      --depth <nbyte>       Depth for search engine (default 10)
      --only <key>          Only show specific instructions
      --filter <key>        Suppress specific mnemonics
      --range <start-end>   Search between two addresses (0x...-0x...)
      --badbytes <byte>     Rejects specific bytes in the gadget's address
      --rawArch <arch>      Specify an arch for a raw file
                            x86|arm|arm64|sparc|mips|ppc|riscv
      --rawMode <mode>      Specify a mode for a raw file 32|64|arm|thumb
      --rawEndian <endian>  Specify an endianness for a raw file little|big
      --re <re>             Regular expression
      --offset <hexaddr>    Specify an offset for gadget addresses
      --ropchain            Enable the ROP chain generation
      --thumb               Use the thumb mode for the search engine (ARM only)
      --console             Use an interactive console for search engine
      --norop               Disable ROP search engine
      --nojop               Disable JOP search engine
      --callPreceded        Only show gadgets which are call-preceded
      --nosys               Disable SYS search engine
      --multibr             Enable multiple branch gadgets
      --all                 Disables the removal of duplicate gadgets
      --noinstr             Disable the gadget instructions console printing
      --dump                Outputs the gadget bytes
      --silent              Disables printing of gadgets during analysis
      --align ALIGN         Align gadgets addresses (in bytes)
      --mipsrop <rtype>     MIPS useful gadgets finder
                            stackfinder|system|tails|lia0|registers

    examples:
      ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86
      ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --ropchain
      ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --depth 3
      ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --string "main"
      ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --string "m..n"
      ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --opcode c9c3
      ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --only "mov|ret"
      ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --only "mov|pop|xor|ret"
      ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --filter "xchg|add|sub|cmov.*"
      ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --norop --nosys
      ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --range 0x08041000-0x08042000
      ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --string main --range 0x080c9aaa-0x080c9aba
      ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --memstr "/bin/sh"
      ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --console
      ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --badbytes "00|01-1f|7f|42"
      ROPgadget.py --binary ./test-suite-binaries/Linux_lib64.so --offset 0xdeadbeef00000000
      ROPgadget.py --binary ./test-suite-binaries/elf-ARMv7-ls --depth 5
      ROPgadget.py --binary ./test-suite-binaries/elf-ARM64-bash --depth 5
      ROPgadget.py --binary ./test-suite-binaries/raw-x86.raw --rawArch=x86 --rawMode=32
      ROPgadget.py --binary ./test-suite-binaries/elf-Linux-RISCV_64 --depth 8

How can I contribute ?
----------------------

- Add system gadgets for PPC, Sparc, ARM64 (Gadgets.addSYSGadgets()).
- Support RISC-V 32-bit.
- Handle bad bytes in data during ROP chain generation.
- Manage big endian in Mach-O format like the ELF class.
- Everything you think is cool :)

Bugs/Patches/Contact
--------------------

Please, report bugs, submit pull requests, etc. on GitHub at https://github.com/JonathanSalwan/ROPgadget

License
-------

See LICENSE_BSD.txt and the license header on all source files.

Screenshots
-----------

<img src="http://shell-storm.org/project/ROPgadget/x64.png" alt="x64"></img>

<img src="http://shell-storm.org/project/ROPgadget/arm.png" alt="ARM"></img>

<img src="http://shell-storm.org/project/ROPgadget/sparc.png" alt="Sparc"></img>

<img src="http://shell-storm.org/project/ROPgadget/mips.png" alt="MIPS"></img>

<img src="http://shell-storm.org/project/ROPgadget/ppc.png" alt="PowerPC"></img>

<img src="http://shell-storm.org/project/ROPgadget/ropchain.png" alt="ROP chain"></img>
