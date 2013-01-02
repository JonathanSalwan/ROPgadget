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

/* gadget necessary for combo importsc */
static char *tab_combo_importsc[] =
{
  "",
  "", CR_AND,           /*set in combo_ropmaker_importsc() */
  "", CR_AND,           /*            //            */
  "", CR_AND,           /*            //            */
  NULL
};

void x86_ropmaker(size_t word_size)
{
  int flag;
  t_gadget *gadgets;
  char **ropsh;
  t_asm *table = (word_size==4)?tab_x8632:tab_x8664;

  if (importsc_mode.opcode.flag)
    ropsh = tab_combo_importsc;
  else
    ropsh = (word_size==4)?tab_x8632_ropmaker:tab_x8664_ropmaker;

  if (importsc_mode.opcode.flag)
    {
      char reg1, reg2, reg3;
      char gad0[32], gad1[32], gad2[32], gad3[32];
      t_asm *gadget = search_instruction(table, ropsh[0]);

      strcpy(gad0, (word_size==4)?"mov %e?x,(%e?x)":"mov %e?x,(%e?x)");
      strcpy(gad1, (word_size==4)?"pop %eXx":"pop %rXx");
      strcpy(gad2, (word_size==4)?"mov (%eXx),%eXx":"mov (%rXx),%rXx");
      strcpy(gad3, (word_size==4)?"mov %eXx,%eXx":"mov %rXx,%rXx");

      if (gadget && gadget->addr)
        {
          reg1 = getreg(gadget->instruction, 1);
          reg2 = getreg(gadget->instruction, 2);
          ropsh[1] = gad1;
          ropsh[3] = gad2;
          ropsh[5] = gad3;
          ropsh[1][6]  = reg2;
          ropsh[3][7]  = reg2;
          ropsh[3][13] = '?';
          gadget = search_instruction(table, ropsh[3]);
          reg3 = getreg(gadget->instruction, 3);
          ropsh[5][6]  = reg3;
          ropsh[5][11] = reg1;

          if (reg3 == reg1) {/* gadget useless */
            ropsh[5] = NULL;
          }
        }
    }

  flag = !combo_ropmaker(ropsh, table, &gadgets);

  if (importsc_mode.opcode.flag)
    {
      if (importsc_mode.opcode.size > (binary->writable_exec_size))
        {
          fprintf(stderr, "\n\t%s/!\\ Possible to make a ROP payload but .got size & .got.plt size isn't sufficient.%s\n", RED, ENDC);
          fprintf(stderr, "  \t%s    got + got.plt = %s" SIZE_FORMAT " bytes%s and your shellcode size is %s" SIZE_FORMAT " bytes%s\n", RED, YELLOW, SIZE_WIDTH, (binary->writable_exec_size), RED, YELLOW, SIZE_WIDTH, (Size)importsc_mode.opcode.size, ENDC);
          return ;
        }
      /* build a python code */
      if (!flag)
        x86_makecode_importsc(gadgets, word_size);
    }
  else
    {
    /* build a python code */
    if (!flag)
      x86_makecode(gadgets, word_size);
    }
  free(gadgets);
}
