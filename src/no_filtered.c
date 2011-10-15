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

int no_filtered(char *instruction)
{
  t_filter_linked *tmp;
  char *org;

  org = instruction;
  tmp = filter_linked;
  if (filter_mode.flag == 0)
    return (0);
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
