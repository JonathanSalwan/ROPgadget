/*
** RopGadget 
** Allan Wirth - http://allanwirth.com/
** Jonathan Salwan - http://twitter.com/JonathanSalwan
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "ropgadget.h"

void syntax(char *str)
{
  hprintf("%sSyntax%s:  %s [FLAGS] <binary> [argv...]\n\n", RED, ENDC, str);
  hprintf("%sFlags%s: \n", RED, ENDC);
  hprintf("    %sSyntax (default is att)%s:\n", GREEN, ENDC);
  hprintf("         -att                      Display all asm in att syntax\n");
  hprintf("         -intel                    Display all asm in intel syntax\n");
  hprintf("    %sGeneration Target (only one can be specified, default is execve /bin/sh)%s:\n", GREEN, ENDC);
  hprintf("         -bind      <port>         Set this flag to make a bind shellcode\n");
  hprintf("         -importsc  <shellcode>    Make custom payload (\\xFF notation)\n");
  hprintf("    %sSearch Filtering (suppresses generation, can be specified multiple times)%s:\n", GREEN, ENDC);
  hprintf("         -filter    <word>         Suppress instructions containing word\n");
  hprintf("         -only      <word>         Only show instructions containg word\n");
  hprintf("    %sSearch Target (supresses generation, default is internal oplist)%s:\n", GREEN, ENDC);
  hprintf("         -opcode    <opcode>       Find opcode in exec segment (\\xFF notation)\n");
  hprintf("         -string    <string>       Find string in read segment ('?' any char)\n");
  hprintf("         -asm       <instructions> Assemble instructions then search for them\n");
  hprintf("    %sSearch Limits%s:\n", GREEN, ENDC);
  hprintf("         -limit     <n>            Only find and show n gadgets/strings\n");
  hprintf("         -map       <start-end>    Search between two addresses (0x...-0x...)\n");
  hprintf("    %sOutput Format (default is python)%s:\n", GREEN, ENDC);
  hprintf("         -pysyn                    Use Python syntax.\n");
  hprintf("         -perlsyn                  Use Perl syntax.\n");
  hprintf("         -csyn                     Use C syntax.\n");
  hprintf("         -phpsyn                   Use PHP syntax.\n");
  hprintf("    %sProgram/Meta%s:\n", GREEN, ENDC);
  hprintf("         -v                        Version\n");
  hprintf("         -h                        Display this help and exit\n");
  hprintf("         -color                    Force color output\n");
  hprintf("         -nocolor                  Disable color output\n");
  hprintf("         -nopayload                Disable payload generation\n\n");

  hprintf("%sArguments%s: \n", RED, ENDC);
  hprintf("    The first non-flag argument is the file to perform operations on.\n");
  hprintf("    If any positional arguments remain after the file, they are\n");
  hprintf("    used as the argv for the execve ROP exploit (thus the first\n");
  hprintf("    should be a full path to an executable).\n\n");

  hprintf("%sEx%s: \n", RED, ENDC);
  hprintf("         %s ./smashme.bin -bind 8080\n", str);
  hprintf("         %s ./smashme.bin -importsc \"\\x6a\\x02\\x58\\xcd\\x80\\xeb\\xf9\"\n", str);
  hprintf("         %s ./smashme.bin -only \"pop\" -filter \"eax\"\n", str);
  hprintf("         %s ./smashme.bin -opcode \"\\xcd\\x80\"\n", str);
  hprintf("         %s ./smashme.bin -intel -asm \"mov eax, [eax] ; ret\"\n", str);
  hprintf("         %s ./smashme.bin -att -asm \"int \\$0x80\"\n", str);
  hprintf("         %s ./smashme.bin -string \"main\"\n", str);
  hprintf("         %s ./smashme.bin -string \"m?in\"\n", str);
  hprintf("         %s ./smashme.bin /bin/echo \"1 4m 4 1337 h4x0r!\"\n", str);
}

void version(void)
{
  hprintf("%sRopGadget%s - " ROPGADGET_VERSION "\n", RED, ENDC);
  hprintf("Jonathan Salwan - twitter @JonathanSalwan\n");
  hprintf("Allan Wirth - allanwirth.com\n");
  hprintf("http://www.shell-storm.org\n");
}
