/*
** RopGadget - Dev v3.3
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2011-10-18
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

/* gadget necessary for combo importsc */
t_ropmaker tab_combo_importsc[] =
{
  {"mov %e?x,(%e?x)"},
  {""},                 /*set in combo_ropmaker_importsc() */
  {""},                 /*            //            */
  {""},                 /*            //            */
  {NULL}
};

static char getfirst(char *str)
{
  char c;

  c= 0x00;
  while (*str !='\0')
    {
      if (*str == ',' && *(str+1) == '(')
        return (*(str-2));
      str++;
    }

  return (c);
}

static char getsecond(char *str)
{
  char c;

  c= 0x00;
  while (*str !='\0')
    {
      if (*str == ',' && *(str+1) == '(')
        return (*(str+4));
      str++;
    }

  return (c);
}

static char getreg3(char *str)
{
  char c;

  c= 0x00;
  while (*str !='\0')
    {
      if (*str == ')' && *(str+1) == ',')
        return (*(str+4));
      str++;
    }

  return (c);
}


void combo_ropmaker_importsc(void)
{
  int i = 0;
  int flag = 0;
  int useless = -1;
  Elf32_Addr addr;
  char reg1, reg2, reg3;
  t_makecode *list_ins = NULL;

  char gad1[] = "pop %eXx";
  char gad2[] = "mov (%eXx),%eXx";
  char gad3[] = "mov %eXx,%eXx";

  addr = search_instruction(tab_combo_importsc[0].instruction);
  if (addr)
    {
      reg1 = getfirst(get_gadget_since_addr(addr));
      reg2 = getsecond(get_gadget_since_addr(addr));
      tab_combo_importsc[1].instruction = gad1;
      tab_combo_importsc[2].instruction = gad2;
      tab_combo_importsc[3].instruction = gad3;
      tab_combo_importsc[1].instruction[6]  = reg2;
      tab_combo_importsc[2].instruction[7]  = reg2;
      tab_combo_importsc[2].instruction[13] = '?';
      addr = search_instruction(tab_combo_importsc[2].instruction);
      reg3 = getreg3(get_gadget_since_addr(addr));
      tab_combo_importsc[3].instruction[6]  = reg3;
      tab_combo_importsc[3].instruction[11] = reg1;

      if (reg3 == reg1) /* gadget useless */
        useless = 3;    /* gadget 3 */
    }

  /* check combo 1 if possible */
  while (tab_combo_importsc[i].instruction)
    {
      if (search_instruction(tab_combo_importsc[i].instruction) == 0 && i != useless)
        {
          flag = 1;
          break;
        }
      i++;
    }

  if (flag == 0)
    fprintf(stdout, "[%s+%s] Combo 1 was found - Possible with the following gadgets.\n", GREEN, ENDC);
  else
    fprintf(stderr, "[%s-%s] Combo 1 was not found, missing instruction(s).\n", RED, ENDC);

  i = 0;
  while (tab_combo_importsc[i].instruction)
    {
      addr = search_instruction(tab_combo_importsc[i].instruction);
      if (addr)
        {
          fprintf(stdout, "\t- %s0x%.8x%s => %s%s%s\n", GREEN, addr, ENDC, GREEN, get_gadget_since_addr(addr), ENDC);
          if (!flag)
            list_ins = add_element(list_ins, get_gadget_since_addr(addr), addr);
        }
      else if (i != useless)
        fprintf(stdout, "\t- %s..........%s => %s%s%s\n", RED, ENDC, RED, tab_combo_importsc[i].instruction, ENDC);
      i++;
    }
  fprintf(stdout, "\t- %s0x%.8x%s => %s.data Addr%s\n", GREEN, Addr_sData, ENDC, GREEN, ENDC);

  if (importsc_mode.size > (importsc_mode.gotsize + importsc_mode.gotpltsize))
    {
      fprintf(stderr, "\n\t%s/!\\ Possible to make a ROP payload but .got size & .got.plz size isn't sufficient.%s\n", RED, ENDC);
      fprintf(stderr, "  \t%s    got + got.plt = %s%d bytes%s and your shellcode size is %s%d bytes%s\n", RED, YELLOW, (importsc_mode.gotsize + importsc_mode.gotpltsize), RED, YELLOW, importsc_mode.size, ENDC);
      return ;
    }
  /* build a python code */
  if (!flag)
    makecode_importsc(list_ins, useless, tab_combo_importsc[1].instruction);
}
