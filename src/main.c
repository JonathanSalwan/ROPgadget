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

#include <getopt.h>

static int v_mode = 0;
static int file_mode = 0;

static struct option long_options[] = {
  {"file", required_argument, &file_mode, 1},
  {"g", no_argument, &flag_g, 1},
  {"elfheader", no_argument, &flag_elfheader, 1},
  {"progheader", no_argument, &flag_progheader, 1},
  {"sectheader", no_argument, &flag_sectheader, 1},
  {"symtab", no_argument, &flag_symtab, 1},
  {"allheader", no_argument, NULL, 0},
  {"v", no_argument, &v_mode, 1},

  {"att", no_argument, &syntaxins.type, ATT},
  {"intel", no_argument, &syntaxins.type, INTEL},
  {"bind", no_argument, &bind_mode.flag, 1},
  {"port", required_argument, NULL, 0},
  {"importsc", required_argument, &importsc_mode.flag, 1},
  {"filter", required_argument, &filter_mode.flag, 1},
  {"only", required_argument, &only_mode.flag, 1},
  {"opcode", required_argument, &opcode_mode.flag, 1},
  {"string", required_argument, &stringmode.flag, 1},
  {"asm", required_argument, &asm_mode.flag, 1},
  {"limit", required_argument, &limitmode.flag, 1},
  {"map", required_argument, &mapmode.flag, 1},

  {"phpsyn", no_argument, &syntaxcode, SYN_PHP},
  {"pysyn", no_argument, &syntaxcode, SYN_PYTHON},
  {"perlsyn", no_argument, &syntaxcode, SYN_PERL},
  {"csyn", no_argument, &syntaxcode, SYN_C},
  {0, 0, 0, 0}
};

#define is_option(s) (!strcmp(long_options[option_index].name, s))
int main(int argc, char **argv) {
  char *file = NULL;
  unsigned char *data;

  set_all_flag(); /* Set default values */

  while (1) {
    int option_index = 0;
    int c = getopt_long_only(argc, argv, "", long_options, &option_index);
    if (c == -1) break;

    if (is_option("file")) {
      file = optarg;
      if (file == NULL || strlen(file) == 0) {
        fprintf(stderr, "%sSyntax%s: -file <binary>\n", RED, ENDC);
        exit(EXIT_FAILURE);
      }
    } else if (is_option("asm")) {
      asm_mode.argument = optarg;
      if (asm_mode.argument == NULL || strlen(asm_mode.argument) == 0) {
        fprintf(stderr, "%sSyntax%s: -asm <instructions>\n", RED, ENDC);
        fprintf(stderr, "%sEx%s:     -asm \"xor %%ebx,%%eax ; ret\"\n", RED, ENDC);
        fprintf(stderr, "        -asm \"int \\$0x80\"\n");
        exit(EXIT_FAILURE);
      }
    } else if (is_option("allheader")) {
      flag_elfheader = 1;
      flag_progheader = 1;
      flag_sectheader = 1;
      flag_symtab = 1;
    } else if (is_option("port")) {
      if (optarg == NULL || strlen(optarg) == 0) {
       fprintf(stderr, "%sSyntax%s: -port <port>\n", RED, ENDC);
       fprintf(stderr, "%sEx%s:     -port 8080\n", RED, ENDC);
       exit(EXIT_FAILURE);
      }
      bind_mode.port = atoi(optarg);
      if (bind_mode.port < 1000 || bind_mode.port > 9999) {
        fprintf(stderr, "%sError port%s: need to set port between 1000 and 9999 (For stack padding)\n", RED, ENDC);
        exit(EXIT_FAILURE);
      }
    } else if (is_option("filter")) {
      if (optarg == NULL || strlen(optarg) == 0) {
        fprintf(stderr, "%sSyntax%s: -filter <word>\n", RED, ENDC);
        fprintf(stderr, "%sEx%s:     -filter \"dec %%edx\"\n", RED, ENDC);
        fprintf(stderr, "        -filter \"pop %%eax\" -filter \"dec\"\n");
        exit(EXIT_FAILURE);
      }
      filter_mode.linked = add_element_word(filter_mode.linked, optarg);
    } else if (is_option("only")) {
      if (optarg == NULL || strlen(optarg) == 0) {
        fprintf(stderr, "%sSyntax%s: -only <keyword>\n", RED, ENDC);
        fprintf(stderr, "%sEx%s:     -only \"dec %%edx\"\n", RED, ENDC);
        fprintf(stderr, "        -only \"pop %%eax\" -only \"dec\"\n");
        exit(EXIT_FAILURE);
      }
      only_mode.linked = add_element_word(only_mode.linked, optarg);
    } else if (is_option("opcode")) {
      if (optarg == NULL || strlen(optarg) == 0) {
        fprintf(stderr, "%sSyntax%s: -opcode <opcode>\n", RED, ENDC);
        fprintf(stderr, "%sEx%s:     -opcode \"\\xcd\\x80\"\n", RED, ENDC);
        exit(EXIT_FAILURE);
      }
      make_opcode(optarg, &opcode_mode);
    } else if (is_option("importsc")) {
      if (optarg == NULL || strlen(optarg) == 0) {
        fprintf(stderr, "%sSyntax%s: -importsc <shellcode>\n", RED, ENDC);
        fprintf(stderr, "%sEx%s: -importsc \"\\x6a\\x02\\x58\\xcd\\x80\\xeb\\xf9\"\n", RED, ENDC);
        exit(EXIT_FAILURE);
      }
      make_opcode(optarg, (t_opcode*)&importsc_mode);
    } else if (is_option("limit")) {
      if (optarg == NULL || strlen(optarg) == 0) {
        fprintf(stderr, "%sSyntax%s: -limit <value>\n", RED, ENDC);
        fprintf(stderr, "%sEx%s:     -limit 100\n", RED, ENDC);
        exit(EXIT_FAILURE);
      }
      limitmode.value = atoi(optarg);
      if (limitmode.value < 0 || limitmode.value > 0xfffe) {
        fprintf(stderr, "%sError%s: limit value\n", RED, ENDC);
        exit(EXIT_FAILURE);
      }
    } else if (is_option("string")) {
      if (optarg == NULL || strlen(optarg) == 0) {
        fprintf(stderr, "%sSyntax%s: -string <string>\n", RED, ENDC);
        fprintf(stderr, "%sEx%s:     -string \"key\"\n", RED, ENDC);
        exit(EXIT_FAILURE);
      }
      stringmode.string = optarg;
      stringmode.size = strlen(optarg);
    } else if (is_option("map")) {
      if (optarg == NULL || strlen(optarg) == 0) {
        fprintf(stderr, "%sSyntax%s: -map <start-end>\n", RED, ENDC);
        fprintf(stderr, "%sEx%s: -map 0x08040000-0x08045000\n", RED, ENDC);
        exit(EXIT_FAILURE);
      }
      mapmode.addr_start = map_get_start(optarg);
      mapmode.addr_end = map_get_end(optarg);
      map_check_error_value();
    }
  }

  if (v_mode) {
    version();
  } else if (!file_mode) {
    syntax(argv[0]);
  }

  data = save_bin_in_memory(file);
  check_elf_format(data);
  check_arch_supported();

  save_section();       /* save all sections in list_sections */
  save_symbols(data);   /* save all symbols in list_symbols */

  if (flag_elfheader)
    display_elf_header();

  if (flag_progheader)
    display_program_header();

  if (flag_sectheader)
    display_section_header();

  if (flag_symtab)
    display_symtab();

  if (asm_mode.flag)
    build_code(asm_mode.argument);

  if (flag_g) {
    search_gadgets(filemode.data, filemode.size);
    if (opcode_mode.flag == 1)
      fprintf(stdout, "\nTotal opcodes found: %s%d%s\n", YELLOW, NbTotalGadFound, ENDC);
    else if (stringmode.flag == 1)
      fprintf(stdout, "\nTotal strings found: %s%d%s\n", YELLOW, NbTotalGadFound, ENDC);
    else
      fprintf(stdout, "\nUnique gadgets found: %s%d%s\n", YELLOW, NbGadFound, ENDC);
  }

  if (flag_sectheader == 0 && flag_progheader == 0 &&
      flag_elfheader  == 0 && flag_symtab == 0 && flag_g == 0)
    help_option();

  free(data);

  return 0;
}
#undef is_option
