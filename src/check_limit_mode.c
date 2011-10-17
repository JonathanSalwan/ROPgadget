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

void check_limit_mode(char **argv)
{
  int i = 0;

  asm_mode.flag = 0;
  while (argv[i] != NULL)
    {
      if (!strcmp(argv[i], "-limit"))
        {
          if (argv[i + 1] != NULL && argv[i + 1][0] != '\0')
            {
              limitmode.flag = 1;
              limitmode.value = atoi(argv[i + 1]);
              if (limitmode.value < 0 || limitmode.value > 0xfffe)
                {
                  fprintf(stderr, "Error value\n");
                  exit(EXIT_FAILURE);
                }
            }
          else
            {
              fprintf(stderr, "Syntax: -limit <value>\n\n");
              fprintf(stderr, "Ex: -limit 100\n");
              exit(EXIT_FAILURE);
            }
        }
      i++;
    }
}
