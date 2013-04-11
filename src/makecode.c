/*
** RopGadget
** Allan Wirth - http://allanwirth.com/
** Jonathan Salwan - http://twitter.com/JonathanSalwan
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

void sc_print_pre_init(void)
{
  switch(syntaxcode) {
  case SYN_PHP:
    oprintf("%s<?php%s\n", BLUE, ENDC);
    break;
  case SYN_PYTHON:
    oprintf("%s#!/usr/bin/python%s\n", BLUE, ENDC);
    break;
  case SYN_PERL:
    oprintf("%s#!/usr/bin/perl%s\n", BLUE, ENDC);
    break;
  default:
    break;
  }
}

void sc_print_init(void)
{
  switch(syntaxcode) {
  case SYN_PYTHON:
    oprintf("%sfrom struct import pack%s\n\n", BLUE, ENDC);
    oprintf("%sp = ''%s\n", BLUE, ENDC);
    break;
  case SYN_C:
    oprintf("%s#include <unistd.h>%s\n", BLUE, ENDC);
    oprintf("%sunsigned char p[] = {%s\n\n", BLUE, ENDC);
    break;
  case SYN_PHP:
  case SYN_PERL:
    oprintf("%s$p = '';%s\n\n", BLUE, ENDC);
    break;
  default:
    break;
  }

  sc_print_comment("Padding goes here");
  oprintf("\n");

  if (binary->object == OBJECT_SHARED) {
    sc_print_comment("This ROP Exploit has been generated for a shared object.");
    sc_print_comment("The addresses of the gadgets will need to be adjusted.");
    switch (syntaxcode) {
    case SYN_PYTHON:
      sc_print_comment("Set this variable to the offset of the shared library");
      oprintf("%soff = 0x0%s\n", BLUE, ENDC);
      break;
    default:
      break;
    }
    oprintf("\n");
  }
}

void sc_print_end(void)
{
  switch(syntaxcode) {
  case SYN_PYTHON:
    oprintf("%sprint p%s\n", BLUE, ENDC);
    break;
  case SYN_C:
    oprintf("%s};%s\n", BLUE, ENDC);
    oprintf("%sint main(void) {%s\n", BLUE, ENDC);
    oprintf("  %swrite(STDOUT_FILENO, p, sizeof(p));%s\n", BLUE, ENDC);
    oprintf("  %sreturn 0;%s\n", BLUE, ENDC);
    oprintf("%s}%s\n", BLUE, ENDC);
    break;
  case SYN_PHP:
    oprintf("%secho $p;%s\n", BLUE, ENDC);
    oprintf("%s?>%s\n", BLUE, ENDC);
    break;
  case SYN_PERL:
    oprintf("%sprint $p;%s\n", BLUE, ENDC);
    break;
  default:
    break;
  }
}

void sc_print_comment(const char *comment)
{
  switch(syntaxcode) {
  case SYN_PHP:
  case SYN_PYTHON:
  case SYN_PERL:
    oprintf("%s# %s%s\n", BLUE, comment, ENDC);
    break;
  case SYN_C:
    oprintf("%s/* %s */%s\n", BLUE, comment, ENDC);
    break;
  default:
    break;
  }
}


static void sc_print_code(Size word, size_t len, const char *comment)
{
  size_t i = 0;

  switch (syntaxcode) {
  case SYN_PYTHON:
    oprintf("%sp += pack(\"<%s\", %s0x%.*x) %s", BLUE, (len==4)?"I":"Q",
        (binary->object == OBJECT_SHARED?"off + ":""), (int)len*2,
        (unsigned int)word, ENDC);
    break;
  case SYN_C:
    oprintf("    %s", BLUE);
    for (i = 0; i < len; i++)
      oprintf("0x%.2hhx, ", (int)((word >> 8*i)&0xff));
    oprintf("%s", ENDC);
    break;
  case SYN_PHP:
  case SYN_PERL:
    oprintf("%s$p .= \"", BLUE);
    for (i = 0; i < len; i++)
      oprintf("\\x%.2hhx", (int)((word >> 8*i)&0xff));
    oprintf("\"; %s", ENDC);
    break;
  default:
    break;
  }
  sc_print_comment(comment);
}

static void sc_print_raw(const char *str, size_t len, size_t word_size, const char *comment)
{
  size_t i;

  Size word = 0;
  for (i = 0; i < word_size; i++)
    word |= (((unsigned int) ((i >= len)?'A':str[i])) & 0xFF)<<(i*8);
  sc_print_code(word, word_size, comment?comment:"Binary Data");
}

static void sc_print_str(const char *quad, size_t len, const char *comment)
{
  size_t i;
  char *tmp = xmalloc(len+1);
  int bad = FALSE;

  memset(tmp, '\0', len+1);
  strncpy(tmp, quad, len);
  /* assume that the caller will deal with overflow */
  while(strlen(tmp) < len)
    tmp[strlen(tmp)] = 'A';
  switch (syntaxcode) {
  case SYN_C:
    oprintf("    %s", BLUE);
    for (i = 0; i < len; i++)
      if (isprint(tmp[i]))
        oprintf("'%c', ", tmp[i]);
      else
        {
          oprintf("0x%.2hhx, ", (int)tmp[i]);
          bad = TRUE;
        }
    oprintf("%s", ENDC);
    break;
  case SYN_PERL:
  case SYN_PHP:
  case SYN_PYTHON:
    oprintf("%s%s \"", BLUE, (syntaxcode==SYN_PYTHON)?"p +=":"$p .=");
    for (i = 0; i < len; i++)
      if (isprint(tmp[i]))
        oprintf("%c", tmp[i]);
      else
        {
          oprintf("\\x%.2hhx", (int)tmp[i]);
          bad = TRUE;
        }
    oprintf("\"%s %s", (syntaxcode==SYN_PYTHON?"":";"), ENDC);
    break;
  default:
    break;
  }
  sc_print_comment(comment?comment:(bad?"Binary string":tmp));
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

void sc_print_sect_addr(int offset, int data, size_t bytes)
{
  char comment[32] = {0};

  snprintf(comment, sizeof(comment), (offset==0)?"@ %s":"@ %s + %d", data?".data":".got", offset);
  sc_print_code((data?binary->writable_offset:binary->writable_exec_offset)+offset, bytes, comment);
}

size_t how_many_pop_x(const char *gadget, const char *pop_reg, enum e_where w)
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

void sc_print_raw_pop(const t_gadget *gad, const char *str, size_t len, size_t bytes)
{
  sc_print_code(gad->gadget->addr, bytes, DISPLAY_SYNTAX(gad->gadget));
  sc_print_padding(how_many_pop_before(gad->gadget->instruction, gad->inst), bytes);
  sc_print_raw(str, len, bytes, NULL);
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

void sc_print_raw_string(const char *str, size_t l, const t_rop_writer *wr, int offset_start, int data, size_t bytes)
{
  size_t i;

  for (i = 0; i < l; i += bytes)
    {
      sc_print_sect_addr_pop(wr->pop_target, offset_start + i, data, bytes);
      sc_print_raw_pop(wr->pop_data, str+i, l-i, bytes);
      sc_print_solo_inst(wr->mov, bytes);
    }
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

  if (num_args == 1) { /* only single argument (binary) so no argv required */
    if (argv_start)
      *argv_start = offset_start + strlen(args[0]);
    if (envp_start)
      *envp_start = offset_start + strlen(args[0]);
  } else {
    if (argv_start != NULL)
      *argv_start = offset;

    vector[i] = -1;

    sc_print_vector(vector, wr, offset, data, bytes);
    if (envp_start != NULL)
      *envp_start = offset + (num_args)*bytes;
  }
  free(vector);

  if (num_args != 1)
    return (offset - offset_start) + (num_args+1)*bytes;
  else
    return (offset_start + strlen(args[0]) + bytes);
}
