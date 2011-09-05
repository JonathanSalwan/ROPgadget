/*
** RopGadget - Release v3.1
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2011-09-05
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
  fprintf(stderr, "         -d      Dump Hexadecimal\n");
  fprintf(stderr, "         -g      Search gadgets and make payload\n");
  fprintf(stderr, "         -v      Version\n");
  fprintf(stderr, "Flags: \n");
  fprintf(stderr, "         -bind   Set this flag for make a bind shellcode (optional) (Default local exploit)\n");
  fprintf(stderr, "         -port   Set a listen port, optional (Default 1337)\n\n");
  fprintf(stderr, "Ex:      %s -g ./smashme.bin -bind -port 8080\n", str);

  exit(EXIT_FAILURE);
}
