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

static void check_pysyn_mode(char **argv)
{
  int i = 0;

  while (argv[i] != NULL)
    {
      if (!strcmp(argv[i], "-pysyn"))
        {
          syntaxcode.flag_pysyn   = 1;
          syntaxcode.flag_csyn    = 0;
          syntaxcode.flag_phpsyn  = 0;
          syntaxcode.flag_perlsyn = 0;
        }
      i++;
    }
}

static void check_csyn_mode(char **argv)
{
  int i = 0;

  while (argv[i] != NULL)
    {
      if (!strcmp(argv[i], "-csyn"))
        {
          syntaxcode.flag_pysyn   = 0;
          syntaxcode.flag_csyn    = 1;
          syntaxcode.flag_phpsyn  = 0;
          syntaxcode.flag_perlsyn = 0;
        }
      i++;
    }
}

static void check_phpsyn_mode(char **argv)
{
  int i = 0;

  while (argv[i] != NULL)
    {
      if (!strcmp(argv[i], "-phpsyn"))
        {
          syntaxcode.flag_pysyn   = 0;
          syntaxcode.flag_csyn    = 0;
          syntaxcode.flag_phpsyn  = 1;
          syntaxcode.flag_perlsyn = 0;
        }
      i++;
    }
}

static void check_perlsyn_mode(char **argv)
{
  int i = 0;

  while (argv[i] != NULL)
    {
      if (!strcmp(argv[i], "-perlsyn"))
        {
          syntaxcode.flag_pysyn   = 0;
          syntaxcode.flag_csyn    = 0;
          syntaxcode.flag_phpsyn  = 0;
          syntaxcode.flag_perlsyn = 1;
        }
      i++;
    }
}

void check_syntax_mode(char **argv)
{
  check_pysyn_mode(argv);
  check_csyn_mode(argv);
  check_phpsyn_mode(argv);
  check_perlsyn_mode(argv);
}
