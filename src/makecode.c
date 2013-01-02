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

static void sc_print_code(Size word, size_t len, const char *comment)
{
  if (len == 4)
    fprintf(stdout, "\t\t%sp += pack(\"<I\", 0x%.8x) # %s%s\n", BLUE, (unsigned int)word, comment, ENDC);
  else if (len == 8)
    fprintf(stdout, "\t\t%sp += pack(\"<Q\", 0x%.16lx) # %s%s\n", BLUE, (unsigned long)word, comment, ENDC);
}

static void sc_print_str(const char *quad, size_t len, const char *comment)
{
  char *tmp = xmalloc(len+1);
  memset(tmp, '\0', len+1);
  strncpy(tmp, quad, len);
  /* assume that the caller will deal with overflow */
  while(strlen(tmp) < len)
    tmp[strlen(tmp)] = 'A';
  fprintf(stdout, "\t\t%sp += \"%s\" # %s%s\n", BLUE, tmp, comment?comment:tmp, ENDC);
  free(tmp);
}

/* display padding */
static void sc_print_padding(size_t i, size_t len)
{
  char *tmp = xmalloc(len+1);
  memset(tmp, 'A', len);
  tmp[len] = '\0';
  for (; i != 0; i--)
    sc_print_str(tmp, len, "padding");
  free(tmp);
}

static void sc_print_sect_addr(int offset, int data, size_t bytes)
{
  char comment[32] = {0};
  snprintf(comment, sizeof(comment), (offset==0)?"@ %s":"@ %s + %d", data?".data":".got", offset);
  sc_print_code((data?binary->writable_offset:binary->writable_exec_offset)+offset, bytes, comment);
}

enum e_where {
  BEFORE,
  AFTER,
  TOTAL
};

#define how_many_pop(g) how_many_pop_x(g, NULL, TOTAL)
#define how_many_pop_before(g, i) how_many_pop_x(g, i, BEFORE)
#define how_many_pop_after(g, i) how_many_pop_x(g, i, AFTER)

static size_t how_many_pop_x(const char *gadget, const char *pop_reg, enum e_where w)
{
  size_t cpt = 0;

  if (w == AFTER)
    gadget = strstr(gadget, pop_reg) + strlen(pop_reg);

  for(; *gadget != '\0'; gadget++)
    if (w == BEFORE && !strncmp(gadget, pop_reg, strlen(pop_reg)))
      break;
    else if (!strncmp(gadget, "pop", 3))
      cpt++;

  return cpt;
}

void sc_print_sect_addr_pop(const t_gadget *gad, int offset, int data, size_t bytes)
{
  sc_print_code(gad->gadget->addr, bytes, DISPLAY_SYNTAX(gad->gadget));
  sc_print_padding(how_many_pop_before(gad->gadget->instruction, gad->inst), bytes);
  sc_print_sect_addr(offset, data, bytes);
  sc_print_padding(how_many_pop_after(gad->gadget->instruction, gad->inst), bytes);
}

void sc_print_str_pop(const t_gadget *gad, const char *str, size_t bytes)
{
  sc_print_code(gad->gadget->addr, bytes, DISPLAY_SYNTAX(gad->gadget));
  sc_print_padding(how_many_pop_before(gad->gadget->instruction, gad->inst), bytes);
  sc_print_str(str, bytes, NULL);
  sc_print_padding(how_many_pop_after(gad->gadget->instruction, gad->inst), bytes);
}

void sc_print_addr_pop(const t_gadget *gad, Address addr, const char *comment, size_t bytes)
{
  sc_print_code(gad->gadget->addr, bytes, DISPLAY_SYNTAX(gad->gadget));
  sc_print_padding(how_many_pop_before(gad->gadget->instruction, gad->inst), bytes);
  sc_print_code(addr, bytes, comment);
  sc_print_padding(how_many_pop_after(gad->gadget->instruction, gad->inst), bytes);
}

/* a 'solo inst' is an instruction that isn't a pop so all the pops must be padded */
void sc_print_solo_inst(const t_gadget *gad, size_t bytes)
{
  sc_print_code(gad->gadget->addr, bytes, DISPLAY_SYNTAX(gad->gadget));
  sc_print_padding(how_many_pop(gad->gadget->instruction), bytes);
}

void sc_print_string(const char *str, const t_rop_writer *wr, int offset_start, int data, size_t bytes)
{
  size_t l = strlen(str), i;
  for (i = 0; i < l; i += bytes)
    {
      sc_print_sect_addr_pop(wr->pop_target, offset_start + i, data, bytes);
      sc_print_str_pop(wr->pop_data, str+i, bytes);
      sc_print_solo_inst(wr->mov, bytes);
    }
  sc_print_sect_addr_pop(wr->pop_target, offset_start + l, data, bytes);
  sc_print_solo_inst(wr->zero_data, bytes);
  sc_print_solo_inst(wr->mov, bytes);
}

void sc_print_vector(const int *args, const t_rop_writer *wr, int offset_start, int data, size_t bytes)
{
  int i;

  for (i = 0; 1; i++)
    {
      sc_print_sect_addr_pop(wr->pop_target, offset_start + bytes *i, data, bytes);
      if (args[i] != -1)
        sc_print_sect_addr_pop(wr->pop_data, args[i], data, bytes);
      else
        sc_print_solo_inst(wr->zero_data, bytes);
      sc_print_solo_inst(wr->mov, bytes);
      if (args[i] == -1)
        return;
    }
}

size_t sc_print_argv(const char * const *args, const t_rop_writer *wr, int offset_start, int data, size_t bytes, int *argv_start, int *envp_start)
{
  int num_args, i, offset;
  int *vector;

  for (num_args = 0; args[num_args]; num_args++) ;

  vector = xmalloc(sizeof(int) * (num_args+1));

  offset = offset_start;

  for (i = 0; args[i]; i++) {
    sc_print_string(args[i], wr, offset, data, bytes);
    vector[i] = offset;
    offset += strlen(args[i])+1;
  }

  if (argv_start != NULL)
    *argv_start = offset;

  vector[i] = -1;

  sc_print_vector(vector, wr, offset, data, bytes);
  free(vector);

  if (envp_start != NULL)
    *envp_start = offset + (num_args)*bytes;

  return (offset - offset_start) + (num_args+1)*bytes;
}

int sc_print_gotwrite(const t_importsc_writer *wr, size_t bytes)
{
  size_t i;
  char comment[32] = {0};

  /* check if all opcodes about shellcode was found in .text */
  if (!check_opcode_was_found())
    {
      fprintf(stdout, "\t%s/!\\ Impossible to generate your shellcode because some opcode was not found.%s\n", RED, ENDC);
      return 0;
    }

  fprintf(stdout, "\t\t%s# Shellcode imported! Generated by RopGadget v3.4.2%s\n", BLUE, ENDC);

  for (i = 0; i != importsc_mode.opcode.size && importsc_mode.poctet != NULL; i++, importsc_mode.poctet = importsc_mode.poctet->back)
    {
      /* pop %edx */
      sprintf(comment, "0x%.2x", importsc_mode.poctet->octet);
      sc_print_addr_pop(wr->pop_gad, importsc_mode.poctet->addr, comment, bytes);

      /* mov (%edx),%ecx */
      sc_print_solo_inst(wr->mov_gad2, bytes);
      if (wr->mov_gad3->gadget)
        /* mov %ecx,%eax */
        sc_print_solo_inst(wr->mov_gad3, bytes);
      /* pop %edx */
      sc_print_sect_addr_pop(wr->pop_gad, i, FALSE, bytes);
      /* mov %eax,(%edx) */
      sc_print_solo_inst(wr->mov_gad4, bytes);
    }
  sc_print_code(binary->writable_exec_offset, bytes, "jump to our shellcode in .got");
  return 1;
}
