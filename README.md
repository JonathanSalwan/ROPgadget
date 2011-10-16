ROPgadget
=========

This tool lets you search your gadgets on your binaries (ELF format) to facilitate your ROP exploitation.</br>
Since version 3.0, ROPgadget has a auto-roper for build your payload automatically with the gadgets found.

* [Web Site](http://shell-storm.org/project/ROPgadget/)



Installation
-----------

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

`-d`        Dump Hexadecimal</br>
`-g`        Search gadgets and make payload</br>
`-v`        Version</br>

<b>Flags</b>

`-bind`                     Set this flag for make a bind shellcode (optional) (Default local exploit)</br>
`-port`      &lt;port&gt;         Set a listen port, optional (Default 1337)</br>
`-importsc`  &lt;shellcode&gt;    Make payload and convert your shellcode in ROP payload</br>
`-filter`    &lt;word&gt;         Word filter (research slowed)</br>
`-only`      &lt;keyword&gt;      Keyword research (research slowed)</br>
`-opcode`    &lt;opcode&gt;       Search a specific opcode on exec segment</br>
`-asm`       &lt;instructions&gt; Search a specific instructions on exec segment</br>
`-elfheader`                Display ELF Header before searching gadgets</br>
`-progheader`               Display Program Header before searching gadgets</br>
`-sectheader`               Display Section Header before searching gadgets</br>

<b>Ex</b>

    ./ROPgadget -g ./smashme.bin -bind -port 8080
    ./ROPgadget -g ./smashme.bin -importsc "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"
    ./ROPgadget -g ./smashme.bin -filter "add %eax" -filter "dec" -bind -port 8080
    ./ROPgadget -g ./smashme.bin -only "pop" -filter "eax"
    ./ROPgadget -g ./smashme.bin -opcode "\xcd\x80"
    ./ROPgadget -g ./smashme.bin -asm "xor %eax,%eax ; ret"
    ./ROPgadget -g ./smashme.bin -asm "int \$0x80"



