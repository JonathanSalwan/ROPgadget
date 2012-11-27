/*
** RopGadget - Release v3.4.2
** Jonathan Salwan - http://twitter.com/JonathanSalwan
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
char *tab_combo_ropsh1[] =
{
  "int $0x80",
  "inc %eax",
  "xor %eax,%eax",
  "mov %e?x,(%e?x)",
  "pop %eax",
  "pop %ebx",
  "pop %ecx",
  "pop %edx",
  NULL
};

/* gadget necessary for combo 2 */
/* don't touch this att syntax for parsing */
char *tab_combo_ropsh2[] =
{
  "sysenter",
  "inc %eax",
  "xor %eax,%eax",
  "mov %e?x,(%e?x)",
  "pop %eax",
  "pop %ebx",
  "pop %ecx",
  "pop %edx",
  "pop %ebp",
  NULL
};

/* gadget necessary for combo importsc */
char *tab_combo_importsc[] =
{
  "mov %e?x,(%e?x)",
  "",                 /*set in combo_ropmaker_importsc() */
  "",                 /*            //            */
  "",                 /*            //            */
  NULL
};

static char getreg(char *str, int i)
{
  for (; *str !='\0'; str++)
    if (i == 1 && *str == ',' && *(str+1) == '(')
      return (*(str-2));
    else if (i == 2 && *str == ',' && *(str+1) == '(')
      return (*(str+4));
    else if (i == 3 && *str == ')' && *(str+1) == ',')
      return (*(str+4));

  return 0;
}

void combo_ropmaker(int target)
{
  int i = 0;
  int flag = 0;
  int useless = -1;
  Elf32_Addr addr;
  char reg1, reg2, reg3;
  t_makecode *list_ins = NULL;

  char **ropsh = target==2?tab_combo_ropsh2:(target == -1?tab_combo_importsc:tab_combo_ropsh1);

  if (target == -1)
    {
      addr = search_instruction(ropsh[0]);
      if (addr)
        {
          reg1 = getreg(get_gadget_since_addr_att(addr), 1);
          reg2 = getreg(get_gadget_since_addr_att(addr), 2);
          ropsh[1] = "pop %eXx";
          ropsh[2] = "mov (%eXx),%eXx";
          ropsh[3] = "mov %eXx,%eXx";
          ropsh[1][6]  = reg2;
          ropsh[2][7]  = reg2;
          ropsh[2][13] = '?';
          addr = search_instruction(ropsh[2]);
          reg3 = getreg(get_gadget_since_addr_att(addr), 3);
          ropsh[3][6]  = reg3;
          ropsh[3][11] = reg1;

          if (reg3 == reg1) /* gadget useless */
            useless = 3;    /* gadget 3 */
        }
    }

  /* check if combo n is possible */
  while (ropsh[i])
    {
      if (search_instruction(ropsh[i]) == 0 && i != useless)
        {
          flag = 1;
          break;
        }
      i++;
    }

  if (target == -1)
    {
      if (flag == 0)
        fprintf(stdout, "[%s+%s] Combo was found - Possible with the following gadgets.\n", GREEN, ENDC);
      else
        fprintf(stderr, "[%s-%s] Combo was not found, missing instruction(s).\n", RED, ENDC);
    }
  else
    {
      if (flag == 0)
        fprintf(stdout, "[%s+%s] Combo %d was found - Possible with the following gadgets. (execve)\n", GREEN, ENDC, target);
      else
        fprintf(stderr, "[%s-%s] Combo %d was not found, missing instruction(s).\n", RED, ENDC, target);
    }

  i = 0;
  while (ropsh[i])
    {
      addr = search_instruction(ropsh[i]);
      if (addr)
        {
          fprintf(stdout, "\t- %s0x%.8x%s => %s%s%s\n", GREEN, addr, ENDC, GREEN, get_gadget_since_addr(addr), ENDC);
          if (!flag)
            list_ins = add_element(list_ins, get_gadget_since_addr_att(addr), addr);
        }
      else
        fprintf(stdout, "\t- %s..........%s => %s%s%s\n", RED, ENDC, RED, ropsh[i], ENDC);
      i++;
    }
  fprintf(stdout, "\t- %s0x%.8x%s => %s.data Addr%s\n", GREEN, Addr_sData, ENDC, GREEN, ENDC);

  if (target == -1)
    {
      if (importsc_mode.size > (importsc_mode.gotsize + importsc_mode.gotpltsize))
        {
          fprintf(stderr, "\n\t%s/!\\ Possible to make a ROP payload but .got size & .got.plz size isn't sufficient.%s\n", RED, ENDC);
          fprintf(stderr, "  \t%s    got + got.plt = %s%d bytes%s and your shellcode size is %s%d bytes%s\n", RED, YELLOW, (importsc_mode.gotsize + importsc_mode.gotpltsize), RED, YELLOW, importsc_mode.size, ENDC);
          return ;
        }
      /* build a python code */
      if (!flag)
        makecode_importsc(list_ins, useless, ropsh[1]);
    }
  else
    {
    /* build a python code */
    if (!flag)
      makecode(list_ins);
    }
}
