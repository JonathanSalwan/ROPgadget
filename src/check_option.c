/*
** RopGadget - Release v3.3.2
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2012-02-14
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

static void help_option(void)
{
  fprintf(stderr, "%sError%s: Need other option with -file\n", RED, ENDC);
  fprintf(stderr, "       Please use the following options\n\n");
  fprintf(stderr, "       %s-g%s              Search gadgets and make payload\n", RED, ENDC);
  fprintf(stderr, "       %s-elfheader%s      Display ELF Header\n", RED, ENDC);
  fprintf(stderr, "       %s-progheader%s     Display Program Header\n", RED, ENDC);
  fprintf(stderr, "       %s-sectheader%s     Display Section Header\n", RED, ENDC);
  fprintf(stderr, "       %s-symtab%s         Display Symbols Table\n", RED, ENDC);
  fprintf(stderr, "       %s-allheader%s      Display ELF/Program/Section/Symbols Header\n", RED, ENDC);
  exit(EXIT_FAILURE);
}

void check_option()
{
  if (flag_sectheader == 0 && flag_progheader == 0 &&
      flag_elfheader  == 0 && flag_symtab == 0 && flag_g == 0)
    help_option();
}
