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

static void set_all_flag(void)
{
  flag_sectheader         = 0;
  flag_progheader         = 0;
  flag_elfheader          = 0;
  flag_symtab             = 0;
  flag_g                  = 0;
  syntaxcode.flag_pysyn   = 1;  /* python syntax by default */
  syntaxcode.flag_csyn    = 0;
  syntaxcode.flag_phpsyn  = 0;
  syntaxcode.flag_perlsyn = 0;
  limitmode.flag          = 0;
  limitmode.value         = -1; /* default unlimited */
  opcode_mode.flag        = 0;
  stringmode.flag         = 0;
  bind_mode.flag          = 0;
  asm_mode.flag           = 0;
  mapmode.flag            = 0;
}

static void check_all_flag(char **argv)
{
  check_allheader_mode(argv);
  check_elfheader_mode(argv);
  check_progheader_mode(argv);
  check_sectheader_mode(argv);
  check_symtab_mode(argv);
  check_bind_mode(argv);
  check_filtre_mode(argv);
  check_only_mode(argv);
  check_opcode_mode(argv);
  check_asm_mode(argv);
  check_importsc_mode(argv);
  check_syntax_mode(argv);
  check_limit_mode(argv);
  check_string_mode(argv);
  check_map_mode(argv);
  check_g_mode(argv);
}

static unsigned char *save_bin_in_memory(char *file)
{
  int fd;
  unsigned char *data;
  struct stat filestat;

  fd = xopen(file, O_RDONLY, 0644);
  stat(file, &filestat);
  filemode.size = filestat.st_size;
  filemode.file = file;
  data = xmalloc(filemode.size * sizeof(char));
  read(fd, data, filemode.size);
  pMapElf = xmmap(0, filemode.size, PROT_READ, MAP_SHARED, fd, 0);
  filemode.data = data;
  pElf_Header = (Elf32_Ehdr *)data;
  pElf32_Shdr = (Elf32_Shdr *)((char *)data + pElf_Header->e_shoff);
  pElf32_Phdr = (Elf32_Phdr *)((char *)data + pElf_Header->e_phoff);
  close(fd);

  return (data);
}

void check_file_mode(char **argv)
{
  unsigned char *data;
  int i = 0;

  while (argv[i] != NULL)
    {
      if (!strcmp(argv[i], "-file"))
        {
          if (argv[i + 1] != NULL && argv[i + 1][0] != '\0')
            {
              data = save_bin_in_memory(argv[i + 1]);
              check_elf_format(data);
              check_arch_supported();
              set_all_flag();
              save_section();       /* save all sections in list_sections */
              save_symbols(data);   /* save all symbols in list_symbols */
              check_all_flag(argv);
              check_option();
              /*search_gadgets(data, filemode.size);*/ /* let's go */
              free(data);
              exit(EXIT_SUCCESS); /* end */
            }
          else
            {
              fprintf(stderr, "%sSyntax%s: -file <binary>\n", RED, ENDC);
              exit(EXIT_FAILURE);
            }
        }
      i++;
    }
}
