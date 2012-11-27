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

#ifndef	 ROPgadget_H
#define	 ROPgadget_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <wchar.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <wait.h>
#include <fcntl.h>
#include <elf.h>

/* colors */
#define _BLUE        "\033[94m"
#define _GREEN       "\033[92m"
#define _YELLOW      "\033[93m"
#define _RED         "\033[91m"
#define _ENDC        "\033[0m"

#define MAGIC_ELF         "\x7F\x45\x4C\x46"
#define TRUE              0
#define FALSE             1

#define SYSV     (pElf_Header->e_ident[EI_OSABI] == ELFOSABI_SYSV)
#define LINUX    (pElf_Header->e_ident[EI_OSABI] == ELFOSABI_LINUX)
#define FREEBSD  (pElf_Header->e_ident[EI_OSABI] == ELFOSABI_FREEBSD)
#define ELF_F    (pElf_Header->e_ident[EI_CLASS] == ELFCLASS32)
#define PROC8632 (pElf_Header->e_machine == EM_386)

/* gadgets series */
typedef struct s_asm
{
  int         flag;
  Elf32_Addr  addr;
  char        *instruction;
  char        *instruction_intel;
  char        *value;
  size_t      size;
} t_asm;

typedef struct s_list_symbols
{
  char                    *name;
  uint32_t                st_name;
  Elf32_Addr              st_value;
  uint32_t                st_size;
  unsigned char           st_info;
  unsigned char           st_other;
  uint16_t                st_shndx;
  struct s_list_symbols   *next;
  struct s_list_symbols   *back;
} t_list_symbols;

/* Linked list for phdr map with read/exec bit */
typedef struct s_map
{
  Elf32_Addr 		addr_start;
  Elf32_Addr 		addr_end;
  struct s_map		*next;
} t_map;

/* Linked list for makecode / variable opcode */
typedef struct s_list_inst
{
  char 			*instruction;
  Elf32_Addr		addr;
  struct s_list_inst 	*next;
} t_list_inst;

/* Linked for sections */
typedef struct s_list_section
{
  char          *name_section;
  Elf32_Addr    addr;
  Elf32_Off     offset;
  size_t        size;
  int           entsize;
  struct s_list_section *next;
} t_list_section;

/* -bind -port */
typedef struct  s_bind_mode
{
  uint16_t port;
  int   flag;
} t_bind_mode;

/* linked list for -filter and -only options */
typedef struct s_word_linked
{
  char    *word;
  struct  s_word_linked  *next;
} t_word_linked;

/* -filter and -only options */
typedef struct s_filter_mode
{
  int   flag;
  t_word_linked *linked;
} t_filter_mode;

/* -opcode */
/* Note that t_imortsc gets cast as this so the first fields must match */
typedef struct s_opcode
{
  unsigned char *opcode;
  size_t size;
  int  flag;
} t_opcode;

/* -string */
typedef struct s_stringmode
{
  char *string;
  int  flag;
} t_stringmode;

/* -asm */
typedef struct s_asm_mode
{
  char *argument;
  unsigned char *opcode;
  int  size;
  int  flag;
} t_asm_mode;

/* linked list for -importsc option */
typedef struct s_char_importsc
{
  unsigned char octet;
  Elf32_Addr addr;
  struct s_char_importsc *next;
  struct s_char_importsc *back;
} t_char_importsc;

/* -importsc */
typedef struct s_importsc
{
  /* Note that this gets cast as a t_opcode so the first fields must match */
  unsigned char *opcode;
  int  size;
  int  flag;
  int  gotsize;
  int  gotpltsize;
  t_char_importsc *poctet;
} t_importsc;

/* -file */
typedef struct s_filemode
{
  char          *file;
  size_t        size;
  unsigned char *data;
} t_filemode;

/* -syntax (not implemented)*/
typedef enum e_syntaxcode
{
  SYN_PHP,
  SYN_PYTHON,
  SYN_C,
  SYN_PERL
} e_syntaxcode;

/* -limit */
typedef struct s_limitmode
{
  int flag;
  int value;
} t_limitmode;

/* -map */
typedef struct s_mapmode
{
  int flag;
  Elf32_Addr addr_start;
  Elf32_Addr addr_end;
} t_mapmode;

/* -att / -intel */
typedef enum e_syntax
{
  INTEL,
  ATT
} e_syntax;

/* globals vars */
Elf32_Ehdr          	*pElf_Header;
Elf32_Phdr          	*pElf32_Phdr;
Elf32_Shdr          	*pElf32_Shdr;
Elf32_Shdr          	*pElf32_HeaderSection;
Elf32_Shdr          	*pElf32_StringSection;
Elf32_Addr  		Addr_sData;
Elf32_Addr              Addr_sGot;

char                    *pMapElf;
t_asm               	*pGadgets;
unsigned int            NbGadFound;
unsigned int            NbTotalGadFound;
t_list_inst             *pVarop;
t_list_section          *list_section;
t_list_symbols          *list_symbols;
int			flag_sectheader;
int			flag_progheader;
int			flag_elfheader;
int                     flag_symtab;
int                     flag_g;

/* flag options */
t_filemode              filemode;	/*  -file 	                  */
t_opcode                opcode_mode;	/*  -opcode 	                  */
t_stringmode            stringmode;     /*  -string                       */
t_asm_mode              asm_mode;	/*  -asm 	                  */
t_importsc              importsc_mode;	/*  -importsc 	                  */
t_bind_mode             bind_mode;	/*  -bind & -port                 */
t_filter_mode           filter_mode;	/*  -filter 	                  */
t_filter_mode           only_mode;	/*  -only 	                  */
t_limitmode             limitmode;      /*  -limit                        */
t_mapmode               mapmode;        /*  -map                          */
e_syntaxcode            syntaxcode;     /*  -pysyn -csyn -phpsyn -perlsyn */
e_syntax                syntaxins;      /*  -intel -att                   */

/* color variables */
char                    *BLUE;
char                    *RED;
char                    *YELLOW;
char                    *GREEN;
char                    *ENDC;

/* core */
const char   		*get_flags(Elf32_Word);
char           		*get_seg(Elf32_Word);
void           		syntax(char *);
void                    version(void);
void           		search_gadgets(unsigned char *, unsigned int);
void           		check_elf_format(unsigned char *);
void          		check_arch_supported(void);
void                    free_add_map(t_map *);
void                    display_program_header(void);
void                    display_section_header(void);
void                    display_elf_header(void);
void                    display_symtab(void);
t_map   		*return_map(int);
char                    *real_string_stringmode(char *, unsigned char *);
void                    print_real_string(char *str);
int 			check_maps(t_map *, Elf32_Addr);
void                    process_filemode(char *);
void                    help_option(void);
t_word_linked           *add_element_word(t_word_linked *, char *);
void                    make_opcode(char *, t_opcode *op);
void                    build_code(char *);
void                    map_parse(char *);
unsigned int            set_cpt_if_mapmode(unsigned int);
unsigned int            check_end_mapmode(unsigned int);
int 			check_interrogation(char *);
char 			*ret_instruction(char *, char *, char *, int);
int			check_if_varop_was_printed(char *);
void 			print_opcode(void);
void                    save_octet(unsigned char *, Elf32_Addr);
int 			search_opcode(const char *, const char *, size_t);
int 			filter(char *, t_filter_mode *);
void                    save_section(void);
void                    save_symbols(unsigned char *);
t_list_section          *get_section(char *);

/* ropmaker */
void                    ropmaker(void);
void      		combo_ropmaker(int);
char 			*get_gadget_since_addr(Elf32_Addr);
char 			*get_gadget_since_addr_att(Elf32_Addr);
Elf32_Addr 		search_instruction(char *);
int                     match(const char *, const char *, size_t);
int                     match2(const char *, const char *, size_t);

/* makecode */
t_list_inst             *add_element(t_list_inst *, char *, Elf32_Addr);
void 			free_list_inst(t_list_inst *);
void			makecode(t_list_inst *);
void                    makecode_importsc(t_list_inst *, int, char *);

/* x86-32bits */
void 			x8632(unsigned char *, unsigned int, t_map *, t_map *);

/* xfunc */
void                    *xmalloc(size_t);
int                     xopen(const char *, int, mode_t);
void                    *xmmap(void *, size_t, int, int, int, off_t);
ssize_t                 xread(int, void *, size_t);
int                     xclose(int);

#endif
