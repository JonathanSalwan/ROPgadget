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

void check_string_mode(char **argv)
{
  int i = 0;

  while (argv[i] != NULL)
    {
      if (!strcmp(argv[i], "-string"))
        {
          if (argv[i + 1] != NULL && argv[i + 1][0] != '\0')
            {
              stringmode.string = argv[i + 1];
              stringmode.size = strlen(argv[i + 1]);
              stringmode.flag = 1;
            }
          else
            {
              fprintf(stderr, "Syntax: -string <string>\n\n");
              fprintf(stderr, "Ex: -string \"key\"\n");
              exit(EXIT_FAILURE);
            }
        }
      i++;
    }
}
