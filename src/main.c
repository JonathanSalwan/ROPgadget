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
