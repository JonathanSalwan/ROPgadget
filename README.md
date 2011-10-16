ROPgadget
=========

<pre>
This tool lets you search your gadgets on your binaries (ELF format) to facilitate your ROP exploitation.
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

`-d`        Dump Hexadecimal
`-g`        Search gadgets add make payload
`-v`        Version

<b>Flags</b>

`-bind`                     Set this flag for make a bind shellcode (optional) (Default local exploit)
`-port`      &lt;port&gt;         Set a listen port, optional (Default 1337)
`-importsc`  &lt;shellcode&gt;    Make payload and convert your shellcode in ROP payload
`-filter`    &lt;word&gt;         Word filter (research slowed)
`-only`      &lt;keyword&gt;      Keyword research (research slowed)
`-opcode`    &lt;opcode&gt;       Search a specific opcode on exec segment
`-asm`       &lt;instructions&gt; Search a specific instructions on exec segment
`-elfheader`                Display ELF Header before searching gadgets
`-progheader`               Display Program Header before searching gadgets
`-sectheader`               Display Section Header before searching gadgets

<b>Ex</b>

    ./ROPgadget -g ./smashme.bin -bind -port 8080
    ./ROPgadget -g ./smashme.bin -importsc "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"
    ./ROPgadget -g ./smashme.bin -filter "add %eax" -filter "dec" -bind -port 8080
    ./ROPgadget -g ./smashme.bin -only "pop" -filter "eax"
    ./ROPgadget -g ./smashme.bin -opcode "\xcd\x80"
    ./ROPgadget -g ./smashme.bin -asm "xor %eax,%eax ; ret"
    ./ROPgadget -g ./smashme.bin -asm "int \$0x80"
</pre>


