/*
** RopGadget - Dev v3.3
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2011-10-16
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
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
  fprintf(stderr, "         -asm       <instructions> Search a specific instructions on exec segment\n");
  fprintf(stderr, "         -elfheader                Display ELF Header before searching gadgets\n");
  fprintf(stderr, "         -progheader               Display Program Header before searching gadgets\n");
  fprintf(stderr, "         -sectheader               Display Section Header before searching gadgets\n\n");
  /*fprintf(stderr, "         -allheader                Display ELF/Program/Section Header before searching gadgets\n\n");*/

  fprintf(stderr, "Ex:      %s -g ./smashme.bin -bind -port 8080\n", str);
  fprintf(stderr, "         %s -g ./smashme.bin -importsc \"\\x6a\\x0b\\x58\\x99\\x52\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x31\\xc9\\xcd\\x80\"\n", str);
  fprintf(stderr, "         %s -g ./smashme.bin -filter \"add %%eax\" -filter \"dec\" -bind -port 8080\n", str);
  fprintf(stderr, "         %s -g ./smashme.bin -only \"pop\" -filter \"eax\"\n", str);
  fprintf(stderr, "         %s -g ./smashme.bin -opcode \"\\xcd\\x80\"\n", str);
  fprintf(stderr, "         %s -g ./smashme.bin -asm \"xor %%eax,%%eax ; ret\"\n", str);
  fprintf(stderr, "         %s -g ./smashme.bin -asm \"int \\$0x80\"\n", str);


  exit(EXIT_SUCCESS);
}
