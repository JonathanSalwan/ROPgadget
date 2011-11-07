/*
** RopGadget - Release v3.3
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2011-11-07
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
