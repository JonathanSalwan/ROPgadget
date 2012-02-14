/*
** RopGadget - Release v3.3.2
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2012-02-14
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
  fprintf(stderr, "%sSyntax%s:  %s <option> <binary> [FLAGS]\n\n", RED, ENDC, str);
  fprintf(stderr, "%sOptions%s: \n", RED, ENDC);
  fprintf(stderr, "         -file                     Load file\n");
  fprintf(stderr, "         -g                        Search gadgets and make payload\n");
  fprintf(stderr, "         -elfheader                Display ELF Header\n");
  fprintf(stderr, "         -progheader               Display Program Header\n");
  fprintf(stderr, "         -sectheader               Display Section Header\n");
  fprintf(stderr, "         -symtab                   Display Symbols Table\n");
  fprintf(stderr, "         -allheader                Display ELF/Program/Section/Symbols Header\n");
  fprintf(stderr, "         -v                        Version\n\n");

  fprintf(stderr, "%sFlags%s: \n", RED, ENDC);
  fprintf(stderr, "         -bind                     Set this flag for make a bind shellcode (optional) (Default local exploit)\n");
  fprintf(stderr, "         -port      <port>         Set a listen port, optional (Default 1337)\n");
  fprintf(stderr, "         -importsc  <shellcode>    Make payload and convert your shellcode in ROP payload\n");
  fprintf(stderr, "         -filter    <word>         Word filter (research slowed)\n");
  fprintf(stderr, "         -only      <keyword>      Keyword research (research slowed)\n");
  fprintf(stderr, "         -opcode    <opcode>       Search a specific opcode on exec segment\n");
  fprintf(stderr, "         -string    <string>       Search a specific hard string on read segment ('?' any char)\n");
  fprintf(stderr, "         -asm       <instructions> Search a specific instructions on exec segment\n");
  fprintf(stderr, "         -limit     <value>        Limit the display of gadgets\n");
  fprintf(stderr, "         -map       <start-end>    Search gadgets on exec segment between two address\n\n");

  fprintf(stderr, "%sEx%s: \n", RED, ENDC);
  fprintf(stderr, "         %s -file ./smashme.bin -g -bind -port 8080\n", str);
  fprintf(stderr, "         %s -file ./smashme.bin -g -importsc \"\\x6a\\x02\\x58\\xcd\\x80\\xeb\\xf9\"\n", str);
  fprintf(stderr, "         %s -file ./smashme.bin -g -filter \"add %%eax\" -filter \"dec\" -bind -port 8080\n", str);
  fprintf(stderr, "         %s -file ./smashme.bin -g -only \"pop\" -filter \"eax\"\n", str);
  fprintf(stderr, "         %s -file ./smashme.bin -g -opcode \"\\xcd\\x80\"\n", str);
  fprintf(stderr, "         %s -file ./smashme.bin -g -asm \"xor %%eax,%%eax ; ret\"\n", str);
  fprintf(stderr, "         %s -file ./smashme.bin -g -asm \"int \\$0x80\"\n", str);
  fprintf(stderr, "         %s -file ./smashme.bin -g -string \"main\"\n", str);
  fprintf(stderr, "         %s -file ./smashme.bin -g -string \"m?in\"\n", str);


  exit(EXIT_SUCCESS);
}
