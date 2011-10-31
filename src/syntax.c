/*
** RopGadget - Dev v3.3
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2011-10-18
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
  fprintf(stderr, "Syntax : %s <option> <binary> [FLAGS]\n\n", str);
  fprintf(stderr, "Options: \n");
  fprintf(stderr, "         -d                        Dump Hexadecimal\n");
  fprintf(stderr, "         -g                        Search gadgets and make payload\n");
  fprintf(stderr, "         -v                        Version\n");
  fprintf(stderr, "Flags: \n");
  fprintf(stderr, "         -bind                     Set this flag for make a bind shellcode (optional) (Default local exploit)\n");
  fprintf(stderr, "         -port      <port>         Set a listen port, optional (Default 1337)\n");
  fprintf(stderr, "         -importsc  <shellcode>    Make payload and convert your shellcode in ROP payload\n");
  fprintf(stderr, "         -filter    <word>         Word filter (research slowed)\n");
  fprintf(stderr, "         -only      <keyword>      Keyword research (research slowed)\n");
  fprintf(stderr, "         -opcode    <opcode>       Search a specific opcode on exec segment\n");
  fprintf(stderr, "         -string    <string>       Search a specific hard string on read segment ('?' any char)\n");
  fprintf(stderr, "         -asm       <instructions> Search a specific instructions on exec segment\n");
  fprintf(stderr, "         -limit     <value>        Limit the display of gadgets\n");
  fprintf(stderr, "         -map       <start-end>    Search gadgets on exec segment between two address\n");
  fprintf(stderr, "         -elfheader                Display ELF Header before searching gadgets\n");
  fprintf(stderr, "         -progheader               Display Program Header before searching gadgets\n");
  fprintf(stderr, "         -sectheader               Display Section Header before searching gadgets\n");
  fprintf(stderr, "         -allheader                Display Section/Program/ELF Header before searching gadgets\n\n");

  fprintf(stderr, "Ex:      %s -g ./smashme.bin -bind -port 8080\n", str);
  fprintf(stderr, "         %s -g ./smashme.bin -importsc \"\\x6a\\x0b\\x58\\x99\\x52\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x31\\xc9\\xcd\\x80\"\n", str);
  fprintf(stderr, "         %s -g ./smashme.bin -filter \"add %%eax\" -filter \"dec\" -bind -port 8080\n", str);
  fprintf(stderr, "         %s -g ./smashme.bin -only \"pop\" -filter \"eax\"\n", str);
  fprintf(stderr, "         %s -g ./smashme.bin -opcode \"\\xcd\\x80\"\n", str);
  fprintf(stderr, "         %s -g ./smashme.bin -asm \"xor %%eax,%%eax ; ret\"\n", str);
  fprintf(stderr, "         %s -g ./smashme.bin -asm \"int \\$0x80\"\n", str);
  fprintf(stderr, "         %s -g ./smashme.bin -string \"main\"\n", str);
  fprintf(stderr, "         %s -g ./smashme.bin -string \"m?in\"\n", str);


  exit(EXIT_SUCCESS);
}
