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


/* gadget necessary for combo 1 */
/* don't touch this att syntax for parsing */
static char *tab_combo_ropsh1[] =
{
  "int $0x80",
    "sysenter",
    "pop %ebp",
    CR_AND,
  CR_OR,
    "inc %eax",
    "inc %ax",
    CR_OR,
    "inc %al",
    CR_OR,
  CR_AND,
  "xor %eax,%eax",
  CR_AND,
  "mov %eax,(%e?x)",
  CR_AND,
  "pop %eax",
  CR_AND,
  "pop %ebx",
  CR_AND,
  "pop %ecx",
  CR_AND,
  "pop %edx",
  CR_AND,
  NULL,
};

/* gadget necessary for combo importsc */
static char *tab_combo_importsc[] =
{
  "mov %e?x,(%e?x)",
  "",  CR_AND,          /*set in combo_ropmaker_importsc() */
  "",  CR_AND,          /*            //            */
  "",  CR_AND,          /*            //            */
  NULL
};

static void x32_combo_ropmaker(int target)
{
  int flag;
  t_list_inst *list_ins = NULL;

  char **ropsh = (target == -1?tab_combo_importsc:tab_combo_ropsh1);

  if (target == -1)
    {
      char reg1, reg2, reg3;
      char gad1[] = "pop %eXx";
      char gad2[] = "mov (%eXx),%eXx";
      char gad3[] = "mov %eXx,%eXx";
      Elf32_Addr addr = search_instruction(tab_x8632, ropsh[0]);
      if (addr)
        {
          reg1 = getreg(get_gadget_since_addr_att(tab_x8632, addr), 1);
          reg2 = getreg(get_gadget_since_addr_att(tab_x8632, addr), 2);
          ropsh[1] = gad1;
          ropsh[3] = gad2;
          ropsh[5] = gad3;
          ropsh[1][6]  = reg2;
          ropsh[3][7]  = reg2;
          ropsh[3][13] = '?';
          addr = search_instruction(tab_x8632, ropsh[3]);
          reg3 = getreg(get_gadget_since_addr_att(tab_x8632, addr), 3);
          ropsh[5][6]  = reg3;
          ropsh[5][11] = reg1;

          if (reg3 == reg1) {/* gadget useless */
            ropsh[5] = NULL;
          }
        }
    }

  flag = !combo_ropmaker(ropsh, tab_x8632, &list_ins);

  if (target == -1)
    {
      if (importsc_mode.size > (importsc_mode.gotsize + importsc_mode.gotpltsize))
        {
          fprintf(stderr, "\n\t%s/!\\ Possible to make a ROP payload but .got size & .got.plt size isn't sufficient.%s\n", RED, ENDC);
          fprintf(stderr, "  \t%s    got + got.plt = %s" SIZE_FORMAT " bytes%s and your shellcode size is %s" SIZE_FORMAT " bytes%s\n", RED, YELLOW, SIZE_WIDTH, (importsc_mode.gotsize + importsc_mode.gotpltsize), RED, YELLOW, SIZE_WIDTH, (Size)importsc_mode.size, ENDC);
          return ;
        }
      /* build a python code */
      if (!flag)
        x8632_makecode_importsc(list_ins, ropsh[1]);
    }
  else
    {
    /* build a python code */
    if (!flag)
      x8632_makecode(list_ins);
    }
  free_list_inst(list_ins);
}

void x8632_ropmaker(void)
{
  if (importsc_mode.flag == 0)
    x32_combo_ropmaker(1);
  else if (importsc_mode.flag == 1)
    x32_combo_ropmaker(-1);
}
