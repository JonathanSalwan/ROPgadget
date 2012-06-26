ROPgadget Tool
==============

This tool lets you search your gadgets on your binaries (ELF format) to facilitate your ROP exploitation.
Since version 3.0, ROPgadget has a auto-roper for build your payload automatically with the gadgets found.

* [Web Site Project](http://shell-storm.org/project/ROPgadget/)


Authors / Contributors
----------------------

    Authors:
    - Jonathan Salwan

    Contributors:
    - Hellman (Bug Fix)
    - Axel "0vercl0k" Souchet (Bug Fix)
    - k3rensk1 (Bug repport)
    - brianairb (Bug Fix)


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

<pre>./ROPgadget &lt;option&gt; &lt;binary&gt; [FLAGS]</pre>

<b>Options</b>

<pre>
-file                     Load file
-g                        Search gadgets and make payload
-elfheader                Display ELF Header
-progheader               Display Program Header
-sectheader               Display Section Header
-symtab                   Display Symbols Table
-allheader                Display ELF/Program/Section/Symbols Header
-v                        Version
</pre>

<b>Flags</b>

<pre>
-att                      Display gadgets information in att syntax
-intel                    Display gadgets information in intel syntax (default)
-bind                     Set this flag for make a bind shellcode (optional) (Default local exploit)
-port      &lt;port&gt;         Set a listen port, optional (Default 1337)
-importsc  &lt;shellcode&gt;    Make payload and convert your shellcode in ROP payload
-filter    &lt;word&gt;         Word filter (research slowed)
-only      &lt;keyword&gt;      Keyword research (research slowed)
-opcode    &lt;opcode&gt;       Search a specific opcode on exec segment
-string    &lt;string&gt;       Search a specific hard string on read segment ('?' any char)
-asm       &lt;instructions&gt; Search a specific instructions on exec segment
-limit     &lt;value&gt;        Limit the display of gadgets
-map       &lt;start-end&gt;    Search gadgets on exec segment between two address
</pre>


<b>Exemple</b>

    ./ROPgadget -file ./smashme.bin -g -bind -port 8080
    ./ROPgadget -file ./smashme.bin -g -importsc "\x6a\x02\x58\xcd\x80\xeb\xf9"
    ./ROPgadget -file ./smashme.bin -g -filter -att "add %eax" -filter "dec" -bind -port 8080
    ./ROPgadget -file ./smashme.bin -g -only "pop" -filter "eax"
    ./ROPgadget -file ./smashme.bin -g -opcode "\xcd\x80"
    ./ROPgadget -file ./smashme.bin -g -asm -intel "mov eax, [eax] ; ret"
    ./ROPgadget -file ./smashme.bin -g -att -asm "int \$0x80"
    ./ROPgadget -file ./smashme.bin -g -string "main"
    ./ROPgadget -file ./smashme.bin -g -string "m?in"

Demo
----
* [Demo exploitation on youtube](http://www.youtube.com/watch?v=cdZ32O1_3KE)


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
