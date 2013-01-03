ROPgadgetX
==============

ROPgadgetX is a major rewrite of the original ROPgadget, designed from 
the start to support 64 bit ROP gadget generation and exploit/payload 
generation.

Major features that have been added to ROPgadgetX:

  - Addition of 64 bit linux support for ROP exploit generation.
  - Addition of 64 bit support for ROP gadget searching.
  - generation of execve ROP exploits with arbitrary argument vectors.
  - payload generation in PHP, C and Perl as well as improved generation for 
    python.
  - color disable/enable switch.
  - improved user friendliness.
  - vastly increased ROP searching speed.
  - Code restructuring for easing addition of new architectures/platforms.
  - general refacoring and code friendiness.

For authors see AUTHORS.

Build
-----

Run `make` you idiot. You're going to need python3 for the 64bit gadget 
generation.

Usage
-----

### Automatic

Most likely what you are going to want is to simply run:

    $ ROPGadget <smashable binary>

A list of interesting gadgets will be printed out to stderr, and if 
possible, a standard execve /bin/sh rop payload will be generated and 
printed to stdout.

If you are not satisfied with the standard /bin/sh payload, you can 
specify additional command line arguments to ROPGadget, which will 
become the argument vector to use in the payload generation step:

    $ ROPGadget <smashable binary> /bin/echo "I 4m 4 1337 h4x0r!!!"

### Custom

If there are a lot of instructions found, you can use the -filter and 
-only options to trim down the output. The -filter option will ignore 
any instructions that contain the passed string. The -only argument 
will only display instructions that match the string provided. Both can 
be specified multiple times, although I'm not entirely convinced this 
is useful.

If you are building your own ROP payload, and you need instructions 
that are not included in the default output, the options you are going 
to be interested in are -asm and -opcode. -opcode lets you specify a 
hex opcode (in the format \x90\x90) on the command line to search for. 
-asm is the same, except that it will assemble the provided argument 
and search for it (not keep in mind the -att and -intel flags to be 
sure to specify the syntax mode you are using!).

If for some reason you want to search for strings in the binary, you 
can use the -string option. This will search the readable sections of 
the binary for the string provided. If you put any question marks in 
the string these will be treated as wildcards.

### Misc

Misc options you might care about are -color and -nocolor, which will 
force/disable the use of color output, respectively (note that when a 
non-terminal device is detected, the output is by default not in color).

The -limit flag lets you specify the maximum number of matches that 
will be searched for. The -map flag lets you limit the search to a 
specific memory range.

The -att and -intel syntax flags let you choose which assembly syntax 
to use. The default is AT&T syntax.

The -phpsyn, -perlsyn, -csyn, and -pysyn flags let you choose the 
format the exploit is generated in. The default is python syntax.

The -bind option is pretty useless. It is equivalent to padding a 
netcat /bin/sh bind handler as the argv.

The -importsc option doesn't work very well because it requires having 
a writable, mapped, executable segment, which mostly doesn't happen. If 
it does, and you are using it, be sure that your shellcode doesn't have 
any NUL bytes in it, because this will cause the output to have NUL 
bytes in it.

When generating ROPs for 64 bit, you are almost guarenteed to have NUL 
bytes in the output. There isn't really anything I can do about this.

Future
------

Features I would like to add in the future are:

  - Support for shared libraries (currently they are ignored).
  - Support for windows binaries.
  - Support for other architecures.
  - Improve optimality of generated payloads.

Bugs/Patches/Contact
--------------------

Send me an email at allan@allanwirth.com or submit a bug report / pull 
request.
