/*
** RopGadget - Release v3.4.2
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** Allan Wirth - http://allanwirth.com/
** http://shell-storm.org
** 2012-11-11
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
  fprintf(stdout, "%sSyntax%s:  %s [FLAGS] <binary>\n\n", RED, ENDC, str);
  fprintf(stdout, "%sFlags%s: \n", RED, ENDC);
  fprintf(stdout, "    %sSyntax (default is intel)%s:\n", GREEN, ENDC);
  fprintf(stdout, "         -att                      Display all asm in att syntax\n");
  fprintf(stdout, "         -intel                    Display all asm in intel syntax\n");
  fprintf(stdout, "    %sGeneration Target (only one can be specified, default is execve /bin/sh)%s:\n", GREEN, ENDC);
  fprintf(stdout, "         -bind      <port>         Set this flag to make a bind shellcode\n");
  fprintf(stdout, "         -importsc  <shellcode>    Make custom payload (\\xFF notation)\n");
  fprintf(stdout, "    %sSearch Filtering (all can be specified multiple times)%s:\n", GREEN, ENDC);
  fprintf(stdout, "         -filter    <word>         Suppress instructions containing word\n");
  fprintf(stdout, "         -only      <word>         Only show instructions containg word\n");
  fprintf(stdout, "    %sSearch Target (only one can be specified, default is internal oplist)%s:\n", GREEN, ENDC);
  fprintf(stdout, "         -opcode    <opcode>       Find opcode in exec segment (\\xFF notation)\n");
  fprintf(stdout, "         -string    <string>       Find string in read segment ('?' any char)\n");
  fprintf(stdout, "         -asm       <instructions> Find instructions in exec segment\n");
  fprintf(stdout, "    %sSearch Limits%s:\n", GREEN, ENDC);
  fprintf(stdout, "         -limit     <n>            Only find and show n gadgets\n");
  fprintf(stdout, "         -map       <start-end>    Search between two addresses (0x...-0x...)\n");
  fprintf(stdout, "    %sProgram/Meta%s:\n", GREEN, ENDC);
  fprintf(stdout, "         -v                        Version\n");
  fprintf(stdout, "         -h                        Display this help and exit\n");
  fprintf(stdout, "         -nocolor                  Disable color output\n");
  fprintf(stdout, "    %sDeprecated (ignored for backward compatability)%s:\n", BLUE, ENDC);
  fprintf(stdout, "         -file                     Load file\n");
  fprintf(stdout, "         -g                        Search gadgets and make payload\n\n");

  fprintf(stdout, "%sEx%s: \n", RED, ENDC);
  fprintf(stdout, "         %s ./smashme.bin -bind 8080\n", str);
  fprintf(stdout, "         %s ./smashme.bin -importsc \"\\x6a\\x02\\x58\\xcd\\x80\\xeb\\xf9\"\n", str);
  fprintf(stdout, "         %s ./smashme.bin -only \"pop\" -filter \"eax\"\n", str);
  fprintf(stdout, "         %s ./smashme.bin -opcode \"\\xcd\\x80\"\n", str);
  fprintf(stdout, "         %s ./smashme.bin -intel -asm \"mov eax, [eax] ; ret\"\n", str);
  fprintf(stdout, "         %s ./smashme.bin -att -asm \"int \\$0x80\"\n", str);
  fprintf(stdout, "         %s ./smashme.bin -string \"main\"\n", str);
  fprintf(stdout, "         %s ./smashme.bin -string \"m?in\"\n", str);
}

void version(void)
{
  fprintf(stdout, "%sRopGadget%s - Release v3.4.2\n", RED, ENDC);
  fprintf(stdout, "Jonathan Salwan - twitter @JonathanSalwan\n");
  fprintf(stdout, "Allan Wirth - allanwirth.com\n");
  fprintf(stdout, "http://www.shell-storm.org\n");
}
