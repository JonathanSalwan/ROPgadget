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
static int h_mode = 0;
static int flag_allheader = 0;
static int flag_sectheader = 0;
static int flag_elfheader = 0;
static int flag_progheader = 0;
static int flag_symtab = 0;

static void set_defaults(void)
{
  syntaxcode              = SYN_PYTHON;  /* python syntax by default */
  limitmode.flag          = 0;
  limitmode.value         = -1; /* default unlimited */
  opcode_mode.flag        = 0;
  stringmode.flag         = 0;
  bind_mode.flag          = 0;
  bind_mode.port          = 1337; /* default port */
  asm_mode.flag           = 0;
  mapmode.flag            = 0;
  filter_mode.flag        = 0;
  filter_mode.linked      = NULL;
  only_mode.flag          = 0;
  only_mode.linked        = NULL;
  opcode_mode.flag        = 0;
  importsc_mode.flag      = 0;
  syntaxins               = INTEL; /* Display with INTEL syntax by default */

  BLUE                    = _BLUE;
  GREEN                   = _GREEN;
  RED                     = _RED;
  YELLOW                  = _YELLOW;
  ENDC                    = _ENDC;
}

static struct option long_options[] = {
  /* These are ignored for backward compat. */
  {"file", required_argument, NULL, 0},
  {"g", no_argument, NULL, 0},

  {"elfheader", no_argument, &flag_elfheader, 1},
  {"progheader", no_argument, &flag_progheader, 1},
  {"sectheader", no_argument, &flag_sectheader, 1},
  {"symtab", no_argument, &flag_symtab, 1},
  {"allheader", no_argument, &flag_allheader, 1},
  {"v", no_argument, &v_mode, 1},
  {"h", no_argument, &h_mode, 1},
  {"nocolor", no_argument, NULL, 0},

  {"att", no_argument, (int *)&syntaxins, ATT},
  {"intel", no_argument, (int *)&syntaxins, INTEL},

  {"bind", no_argument, &bind_mode.flag, 1},
  {"importsc", required_argument, &importsc_mode.flag, 1},

  {"filter", required_argument, &filter_mode.flag, 1},
  {"only", required_argument, &only_mode.flag, 1},

  {"opcode", required_argument, &opcode_mode.flag, 1},
  {"string", required_argument, &stringmode.flag, 1},
  {"asm", required_argument, &asm_mode.flag, 1},

  {"limit", required_argument, &limitmode.flag, 1},
  {"map", required_argument, &mapmode.flag, 1},

  {"phpsyn", no_argument, (int *)&syntaxcode, SYN_PHP},
  {"pysyn", no_argument, (int *)&syntaxcode, SYN_PYTHON},
  {"perlsyn", no_argument, (int *)&syntaxcode, SYN_PERL},
  {"csyn", no_argument, (int *)&syntaxcode, SYN_C},
  {0, 0, 0, 0}
};

#define is_option(s) (!strcmp(long_options[option_index].name, s))
int main(int argc, char **argv) {
  char *file = NULL;

  set_defaults(); /* Set default values */

  while (1) {
    int option_index = 0;
    int c = getopt_long_only(argc, argv, "", long_options, &option_index);
    if (c == -1) break;

    if (is_option("asm")) {
      asm_mode.argument = optarg;
      if (asm_mode.argument == NULL || strlen(asm_mode.argument) == 0) {
        fprintf(stderr, "%sSyntax%s: -asm <instructions>\n", RED, ENDC);
        fprintf(stderr, "%sEx%s:     -asm \"xor %%ebx,%%eax ; ret\"\n", RED, ENDC);
        fprintf(stderr, "        -asm \"int \\$0x80\"\n");
        return 1;
      }
    } else if (is_option("bind")) {
      if (optarg == NULL || strlen(optarg) == 0) {
       fprintf(stderr, "%sSyntax%s: -bind <port>\n", RED, ENDC);
       fprintf(stderr, "%sEx%s:     -bind 8080\n", RED, ENDC);
       return 1;
      }
      bind_mode.port = atoi(optarg);
      if (bind_mode.port < 1000 || bind_mode.port > 9999) {
        fprintf(stderr, "%sError port%s: need to set port between 1000 and 9999 (For stack padding)\n", RED, ENDC);
        return 1;
      }
    } else if (is_option("filter")) {
      if (optarg == NULL || strlen(optarg) == 0) {
        fprintf(stderr, "%sSyntax%s: -filter <word>\n", RED, ENDC);
        fprintf(stderr, "%sEx%s:     -filter \"dec %%edx\"\n", RED, ENDC);
        fprintf(stderr, "        -filter \"pop %%eax\" -filter \"dec\"\n");
        return 1;
      }
      filter_mode.linked = add_element_word(filter_mode.linked, optarg);
    } else if (is_option("only")) {
      if (optarg == NULL || strlen(optarg) == 0) {
        fprintf(stderr, "%sSyntax%s: -only <keyword>\n", RED, ENDC);
        fprintf(stderr, "%sEx%s:     -only \"dec %%edx\"\n", RED, ENDC);
        fprintf(stderr, "        -only \"pop %%eax\" -only \"dec\"\n");
        return 1;
      }
      only_mode.linked = add_element_word(only_mode.linked, optarg);
    } else if (is_option("opcode")) {
      if (optarg == NULL || strlen(optarg) == 0) {
        fprintf(stderr, "%sSyntax%s: -opcode <opcode>\n", RED, ENDC);
        fprintf(stderr, "%sEx%s:     -opcode \"\\xcd\\x80\"\n", RED, ENDC);
        return 1;
      }
      make_opcode(optarg, &opcode_mode);
    } else if (is_option("importsc")) {
      if (optarg == NULL || strlen(optarg) == 0) {
        fprintf(stderr, "%sSyntax%s: -importsc <shellcode>\n", RED, ENDC);
        fprintf(stderr, "%sEx%s: -importsc \"\\x6a\\x02\\x58\\xcd\\x80\\xeb\\xf9\"\n", RED, ENDC);
        return 1;
      }
      make_opcode(optarg, (t_opcode*)&importsc_mode);
    } else if (is_option("limit")) {
      if (optarg == NULL || strlen(optarg) == 0) {
        fprintf(stderr, "%sSyntax%s: -limit <value>\n", RED, ENDC);
        fprintf(stderr, "%sEx%s:     -limit 100\n", RED, ENDC);
        return 1;
      }
      limitmode.value = atoi(optarg);
      if (limitmode.value < 0 || limitmode.value > 0xfffe) {
        fprintf(stderr, "%sError%s: limit value\n", RED, ENDC);
        return 1;
      }
    } else if (is_option("string")) {
      if (optarg == NULL || strlen(optarg) == 0) {
        fprintf(stderr, "%sSyntax%s: -string <string>\n", RED, ENDC);
        fprintf(stderr, "%sEx%s:     -string \"key\"\n", RED, ENDC);
        return 1;
      }
      stringmode.string = optarg;
    } else if (is_option("map")) {
      if (optarg == NULL || strlen(optarg) == 0) {
        fprintf(stderr, "%sSyntax%s: -map <start-end>\n", RED, ENDC);
        fprintf(stderr, "%sEx%s: -map 0x08040000-0x08045000\n", RED, ENDC);
        return 1;
      }
      map_parse(optarg);
    } else if (is_option("nocolor")) {
      BLUE = "";
      RED = "";
      YELLOW = "";
      GREEN = "";
      ENDC = "";
    }
  }

  if (v_mode) {
    version();
    return 0;
  } else if (h_mode) {
    syntax(argv[0]);
    return 0;
  } else if (optind == argc) {
    syntax(argv[0]);
    return 1;
  }

  file = argv[optind];

  if (bind_mode.flag && importsc_mode.flag) {
    fprintf(stderr, "\t%sError. -bind and -importsc are mutually exclusive.%s\n", RED, ENDC);
    return 1;
  }

  if (stringmode.flag + opcode_mode.flag + asm_mode.flag > 1) {
    fprintf(stderr, "\t%sError. Only one of -string, -opcode and -asm can be specified.%s\n", RED, ENDC);
    return 1;
  }

  process_filemode(file);
  check_elf_format(filemode.data);
  check_arch_supported();

  save_section();       /* save all sections in list_sections */
  save_symbols(filemode.data);   /* save all symbols in list_symbols */

  if (flag_elfheader || flag_allheader)
    display_elf_header();

  if (flag_progheader || flag_allheader)
    display_program_header();

  if (flag_sectheader || flag_allheader)
    display_section_header();

  if (flag_symtab || flag_allheader)
    display_symtab();

  if (flag_allheader || flag_elfheader || flag_progheader || flag_sectheader || flag_symtab)
    return 1;

  search_gadgets(filemode.data, filemode.size);

  free(filemode.data);

  return 0;
}
#undef is_option
