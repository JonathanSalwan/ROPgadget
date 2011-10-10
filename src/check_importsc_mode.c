/*
** RopGadget - Release v3.2
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2011-10-10
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

static void check_char(char c)
{
  if (c >= '0' && c <= '9')
    return ;
  else if (c >= 'a' && c <= 'f')
    return ;
  else if (c >= 'A' && c <= 'F')
    return ;

  fprintf(stderr, "%sOpcode error%s: No hexa byte\n", RED, ENDC);
  exit(EXIT_FAILURE);
}

static void make_opcode(char *str)
{
  int i = 0;
  unsigned char *ptr;
  int size;

  size = size_opcode(str);
  importsc_mode.size = size;
  ptr = malloc(size * sizeof(char));
  memset(ptr, 0x00, size * sizeof(char));
  while (i != size)
    {
      if (*str != '\\' && *str != 'x')
        {
          fprintf(stderr, "%sSyntax error%s: Bad separator\n", RED, ENDC);
          fprintf(stderr, "              Please respect this syntax: \\xcd\\x80\n");
          exit(EXIT_FAILURE);
        }
      while (*str == '\\' || *str == 'x')
        str++;
      check_char(*str);
      check_char(*(str + 1));
      ptr[i] = strtol(str, NULL, 16);
      i++;
      str += 2;
    }
  importsc_mode.opcode = ptr;
}

void check_importsc_mode(char **argv)
{
  int i = 0;

  importsc_mode.flag = 0;
  while (argv[i] != NULL)
    {
      if (!strcmp(argv[i], "-importsc"))
        {
          if (argv[i + 1] != NULL && argv[i + 1][0] != '\0')
            {
              importsc_mode.argument = argv[i + 1];
              importsc_mode.flag = 1;
              make_opcode(argv[i + 1]);
            }
          else
            {
              fprintf(stderr, "Syntax: -importsc <shellcode>\n\n");
              fprintf(stderr, "Ex: -importsc \"\\x6a\\x0b\\x58\\x99\\x52\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x31\\xc9\\xcd\\x80\"\n");
              exit(EXIT_FAILURE);
            }
        }
      i++;
    }
}
