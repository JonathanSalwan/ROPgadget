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

void check_bind_mode(char **argv)
{
  int i = 0;

  memset(bind_mode.port, 0x00, sizeof(bind_mode.port));
  strcpy(bind_mode.port, "1337"); /* set a default port */
  bind_mode.flag = 0;
  while (argv[i] != NULL)
    {
      if (!strcmp(argv[i], "-bind"))
        bind_mode.flag = 1;
      if (!strcmp(argv[i], "-port"))
        {
          if (argv[i + 1] == NULL)
            {
              fprintf(stderr, "Error: syntax -port <port>\n");
              exit(EXIT_FAILURE);
            }
          if (atoi(argv[i + 1]) < 1000 || atoi(argv[i + 1]) > 9999)
            {
              fprintf(stderr, "Error port: need to set port between 1000 and 9999 (For stack padding)\n");
              exit(EXIT_FAILURE);
            }
          strcpy(bind_mode.port, argv[i + 1]);
        }
      i++;
    }
}
