/*
** RopGadget - Dev v3.3
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2011-10-16
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

#include "ropgadget.h"

int main(__attribute__ ((unused))int argc, char **argv)
{
/*
    da_addr_t addr = 0;

    da_word_t data = 0x0100a0e1;

    da_instr_t instr;
    da_instr_args_t args;
    da_instr_parse(&instr, data, 1);
    da_instr_parse_args(&args, &instr);

    da_instr_fprint(stdout, &instr, &args, addr);
    printf("\n");

    addr += sizeof(da_word_t);
*/
  check_v_mode(argv);
  check_g_mode(argv);
  check_d_mode(argv);

  syntax(argv[0]);
  return(0);
}
