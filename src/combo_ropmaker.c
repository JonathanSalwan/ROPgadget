/*
** RopGadget - Release v3.4.2
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** Allan Wirth - http://allanwirth.com/
** http://shell-storm.org
** 2012-11-11
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

int combo_ropmaker(char **ropsh, t_asm *table, t_list_inst **list_ins)
{
  int i;
  int flag = 0;
  int ff = 0; /* Fast forward */
  Elf64_Addr addr;
  *list_ins = NULL;

  /* check if combo n is possible */
  for ( i = 0; ropsh[i]; i++) {
    addr = search_instruction(table, ropsh[i]);
    if (addr)
      fprintf(stdout, "\t- %s" ADDR_FORMAT "%s => %s%s%s\n", GREEN, ADDR_WIDTH, addr,
          ENDC, GREEN, get_gadget_since_addr(table, addr), ENDC);
    else
      fprintf(stdout, "\t- %s..........%s => %s%s%s\n", RED, ENDC, RED, ropsh[i], ENDC);
    if (ff) {
      if (!ropsh[i+1]) {
        i++;
        ff = 0;
      }
      continue;
    }
    if (!addr && ropsh[i+1] == NULL) {
      flag = 1;
      *list_ins = add_element(*list_ins, "", 0);
      i++;
    } else if (addr) {
      *list_ins = add_element(*list_ins, get_gadget_since_addr_att(table, addr), addr);
      if (!ropsh[i+1]) i++;
      else ff = 1;
    }
  }

  fprintf(stdout, "\t- %s" ADDR_FORMAT "%s => %s.data Addr%s\n", GREEN, ADDR_WIDTH, (Elf64_Addr)Addr_sData, ENDC, GREEN, ENDC);

  if (!flag)
    fprintf(stdout, "[%s+%s] Combo was found!\n", GREEN, ENDC);
  else
    fprintf(stderr, "[%s-%s] Combo was not found.\n", RED, ENDC);

  return !flag;
}
