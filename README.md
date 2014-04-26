ROPgadget Tool
================

<p style="text-align: justify;">This tool lets you search your gadgets on 
your binaries to facilitate your ROP exploitation. ROPgadget supports ELF/PE/Mach-O 
format on x86, x64, ARM, PowerPC, SPARC and MIPS architectures. Since the version 5, 
ROPgadget has a new core which is written in Python using Capstone disassembly framework
for the gadgets search engine - The older version can be found in the Archives directory 
but it will not be maintained.</p>

Install
-------

If you want to use ROPgadget, you have to install Capstone first. 

For the Capstone's installation on nix machine:

    $ cd ./dependencies/capstone-next
    $ ./make.sh
    $ sudo ./make.sh install
    $ cd ./bindings/python
    $ sudo make install

Capstone supports multi-platforms (windows, ios, android, cygwin...). For the cross-compilation, 
please refer to the https://github.com/JonathanSalwan/ROPgadget/blob/dev/dependencies/capstone-next/COMPILE.TXT 
file.


Usage
-----

    usage: ROPgadget.py [-h] [-v] [-c] [--binary <binary>] [--opcode <opcodes>]
                        [--string <string>] [--memstr <string>] [--depth <nbyte>]
                        [--only <key>] [--filter <key>] [--range <start-end>]
                        [--badbytes <byte>] [--ropchain] [--thumb] [--console]
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
      --ropchain           Enable the ROP chain generation
      --thumb              Use the thumb mode for the search engine. (ARM only)
      --console            Use an interactive console for search engine
      --norop              Disable ROP search engine
      --nojop              Disable JOP search engine
      --nosys              Disable SYS search engine

    console commands:
      badbytes             Rejects specific bytes in the gadget's address
      depth                Set the depth search engine
      display              Display all gadgets
      help                 Display the help
      load                 Load all gadgets
      quit                 Quit the console mode
      search               Search specific keywords or not

How can I contribute ?
----------------------

- Add ARM64
- Use Z3 to solve the ROP chain
- Add system gadgets for PPC, Sparc (Gadgets.addSYSGadgets())
- Manage big endian in Mach-O format like the ELF classe.
- Everything you think is cool :)

Bugs/Patches/Contact
--------------------

<p style="text-align:justify;">Please report bugs, submit pull requests, etc. on github at https://github.com/JonathanSalwan/ROPgadget
The offical page is on shell-storm.org at http://shell-storm.org/project/ROPgadget/</p>

License
-------

<p style="text-align:justify;">See COPYING and the license header on all source files. 
For the files in the dependencies/ there are individual licenses in each folder.</p>

