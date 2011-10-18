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

static int pose_var(char *str)
{
  int i = 0;
  int size;

  size = stringmode.size;
  while (size != 0 && str[i] != '?')
    {
      i++;
      size--;
    }

  return (i);
}

static int check_var(char *str)
{
  int size;

  size = stringmode.size;
  while (size != 0)
    {
      if (*str == '?')
        return (1);
      str++;
      size--;
    }
  return (0);
}

void print_real_string(char *str)
{
  int size;

  size = stringmode.size;
  while (size != 0)
    {
      if (*str >= 0x20 && *str <= 0x7e)
        fprintf(stdout, "%c", *str);
      else
        fprintf(stdout, "\\x%.2x", (unsigned char)(*(str)));
      str++;
      size--;
    }
}

char *real_string_stringmode(char *base_string, unsigned char *data)
{
  char *real_string;
  int  size;
  int  i = 0;

  size = (strlen(base_string) + 1);
  real_string = malloc(size * sizeof(char));
  if (real_string == NULL)
    {
      fprintf(stderr, "Error malloc\n");
      exit(EXIT_FAILURE);
    }

  strncpy(real_string, base_string, size);

  while (check_var(real_string) == 1)
    {
      i = pose_var(real_string);
      real_string[i] = data[i];
    }

  return (real_string);
}
