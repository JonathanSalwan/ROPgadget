ROPgadget Tool
==============

This tool lets you search your gadgets on your binaries (ELF format) to facilitate your ROP exploitation.
Since version 3.0, ROPgadget has a auto-roper for build your payload automatically with the gadgets found.

* [Web Site Project](http://shell-storm.org/project/ROPgadget/)



Installation
------------

    git clone git@github.com:JonathanSalwan/ROPgadget.git
    cd ./ROPgadget
    make
    su
    make install


Usage
-----

<b>Syntax</b>

./ROPgadget &lt;option&gt; &lt;binary&gt; [FLAGS]

<b>Options</b>

* `-d`        Dump Hexadecimal
* `-g`        Search gadgets add make payload
* `-v`        Version


<b>Flags</b>

<pre>
-bind                     Set this flag for make a bind shellcode (optional) (Default local exploit)
-port      &lt;port&gt;         Set a listen port, optional (Default 1337)
-importsc  &lt;shellcode&gt;    Make payload and convert your shellcode in ROP payload
-filter    &lt;word&gt;         Word filter (research slowed)
-only      &lt;keyword&gt;      Keyword research (research slowed)
-opcode    &lt;opcode&gt;       Search a specific opcode on exec segment
-string    &lt;string&gt;       Search a specific hard string on read segment ('?' any char)
-asm       &lt;instructions&gt; Search a specific instructions on exec segment
-limit     &lt;value&gt;        Limit the display of gadgets
-elfheader                Display ELF Header before searching gadgets
-progheader               Display Program Header before searching gadgets
-sectheader               Display Section Header before searching gadgets
</pre>


<b>Exemple</b>

    ./ROPgadget -g ./smashme.bin -bind -port 8080
    ./ROPgadget -g ./smashme.bin -importsc "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"
    ./ROPgadget -g ./smashme.bin -filter "add %eax" -filter "dec" -bind -port 8080
    ./ROPgadget -g ./smashme.bin -only "pop" -filter "eax"
    ./ROPgadget -g ./smashme.bin -opcode "\xcd\x80"
    ./ROPgadget -g ./smashme.bin -asm "xor %eax,%eax ; ret"
    ./ROPgadget -g ./smashme.bin -asm "int \$0x80"
    ./ROPgadget -g ./smashme.bin -string "main"
    ./ROPgadget -g ./smashme.bin -string "ma?n"

Memo
----

The tool can find a gadget in other gadget.

ropgadget find it: `0x0806bb68: mov $0x5e5bf089,%edi | ret`

The original gadget is:
<pre>
│                                                                            │
│ 806bb68 ! bf                               db          0bfh                │
│ 806bb69 !                                                                  │
│ ....... ! loc_806bb69:                    ;xref j806bb4c j806bb53 j806bb5e │
│ ....... ! 89f0                             mov         eax, esi            │
│ 806bb6b !                                                                  │
│ ....... ! loc_806bb6b:                    ;xref j806bb2e j806bb36 j806bb3d │
│ ....... !                                 ;xref j806bb44 j806bb70 j806bb77 │
│ ....... !                                 ;xref j806bb7e                   │
│ ....... ! 5b                               pop         ebx                 │
│ 806bb6c ! 5e                               pop         esi                 │
│ 806bb6d ! c3                               ret                             │
│ 806bb6e !                                                                  │

</pre>
