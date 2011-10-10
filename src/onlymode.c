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

int onlymode(char *instruction)
{
  t_only_linked *tmp;
  char *org;

  org = instruction;
  tmp = only_linked;
  if (only_mode.flag == 0)
    return (1);
  while (tmp != NULL)
    {
      while (*instruction != '\0')
        {
          if (!strncmp(instruction, tmp->word, strlen(tmp->word)))
            return (1);
          instruction++;
        }
      instruction = org;
      tmp = tmp->next;
    }
  return (0);
}
