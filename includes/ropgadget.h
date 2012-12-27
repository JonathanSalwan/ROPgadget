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
#define TRUE              1
#define FALSE             0

#define SYSV     (filemode.data[EI_OSABI] == ELFOSABI_SYSV)
#define LINUX    (filemode.data[EI_OSABI] == ELFOSABI_LINUX)
#define FREEBSD  (filemode.data[EI_OSABI] == ELFOSABI_FREEBSD)
#define ELF_F    (filemode.data[EI_CLASS] == ELFCLASS32)
#define ELF_F64  (filemode.data[EI_CLASS] == ELFCLASS64)
#define PROC8632 (pElf32_Header->e_machine == EM_386)
#define PROC8664 (pElf64_Header->e_machine == EM_X86_64)

/* type definitions for easing transition */
typedef Elf64_Addr Address;
typedef Elf64_Off Offset;
typedef uint64_t Size;
#define ADDR_FORMAT "0x%.*lx"
#define SIZE_FORMAT "0x%.*ld"

#define ADDR_WIDTH ((containerType == CONTAINER_ELF32)?8:16)
#define SIZE_WIDTH ADDR_WIDTH

/* does something to the phdr/header struct with a given type, based on 32 or 64 bits */
/* Joshua 7:20 - Achan replied, "It is true! I have sinned against the LORD, the God of Israel." */
#define PHDR(X, t) (containerType == CONTAINER_ELF32?((t)(pElf32_Phdr X)):((t)(pElf64_Phdr X)))
#define EHDR(X, t) (containerType == CONTAINER_ELF32?((t)(pElf32_Header X)):((t)(pElf64_Header X)))

/* These are for the Reverse Polish Notation used to define shellcodes (CR = combo ropmaker) */
#define CR_AND "&"
#define CR_OR "|"

typedef enum {
  CONTAINER_ELF32,
  CONTAINER_ELF64
} e_container;

/* gadgets series */
typedef struct s_asm
{
  int         flag;
  Address     addr;
  char        *instruction;
  char        *instruction_intel;
  char        *value;
  size_t      size;
} t_asm;

/* Linked list for phdr map with read/exec bit */
typedef struct s_map
{
  Address 		addr_start;
  Address 		addr_end;
  struct s_map		*next;
} t_map;

/* Linked list for makecode / variable opcode */
typedef struct s_list_inst
{
  char 			*instruction;
  Address		addr;
  struct s_list_inst 	*next;
} t_list_inst;

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
  Address addr;
  struct s_char_importsc *next;
  struct s_char_importsc *back;
} t_char_importsc;

/* -importsc */
typedef struct s_importsc
{
  /* Note that this gets cast as a t_opcode so the first fields must match */
  unsigned char *opcode;
  size_t  size;
  int  flag;
  Size  gotsize;
  Size  gotpltsize;
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
  Address addr_start;
  Address addr_end;
} t_mapmode;

/* -att / -intel */
typedef enum _e_syntax
{
  INTEL,
  ATT
} e_syntax;

/* globals vars */
Elf32_Ehdr          	*pElf32_Header;
Elf64_Ehdr          	*pElf64_Header;

Elf32_Phdr *pElf32_Phdr;
Elf64_Phdr *pElf64_Phdr;

Address  		Addr_sData;
Address              Addr_sGot;

unsigned int            NbGadFound;
unsigned int            NbTotalGadFound;
t_list_inst             *pVarop;
e_container             containerType;

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
void           		syntax(char *);
void                    version(void);
void           		search_gadgets(unsigned char *, unsigned int);

/* maps */
void                    free_add_map(t_map *);
t_map   		*return_map(int);
int			check_maps(t_map *, Address);
void                    map_parse(char *);
unsigned int            set_cpt_if_mapmode(unsigned int);
unsigned int            check_end_mapmode(unsigned int);

/* stringmode */
char                    *real_string_stringmode(char *, unsigned char *);
void                    print_real_string(char *str);

/* filemode */
void                    process_filemode(char *);

/* word mode */
t_word_linked           *add_element_word(t_word_linked *, char *);
int 			filter(char *, t_filter_mode *);

/* opcode/importsc */
void                    make_opcode(char *, t_opcode *op);
void                    save_octet(unsigned char *, Address);
void 			print_opcode(void);

/* varop */
int 			check_interrogation(const char *);
char 			*ret_instruction(const unsigned char *, const char *, const char *, int);
int			check_if_varop_was_printed(const char *);
char                    getreg(const char *, int i);

/* ropmaker */
char 			*get_gadget_since_addr_by_type(t_asm *, Address, e_syntax);
#define get_gadget_since_addr(a, b) get_gadget_since_addr_by_type(a, b, syntaxins)
#define get_gadget_since_addr_att(a, b) get_gadget_since_addr_by_type(a, b, ATT)
Address 		search_instruction(t_asm *, char *);
int                     match(const char *, const char *);
int                     match2(const unsigned char *, const unsigned char *, size_t);

/* makecode */
t_list_inst             *add_element(t_list_inst *, char *, Address);
void 			free_list_inst(t_list_inst *);
void 			find_all_gadgets(unsigned char *, unsigned int, t_map *, t_map *, t_asm *);
int                     combo_ropmaker(char **, t_asm *, t_list_inst **);
Address                 ret_addr_makecodefunc(t_list_inst *, const char *);
void                    sc_print_str(const char *, size_t, const char *);
void                    sc_print_padding(size_t, size_t);
void                    sc_print_code(Size, size_t, const char *);
void                    sc_print_sect_addr(int, int, size_t);

void                    sc_print_code_padded(int, const char *, const char *, size_t);
void                    sc_print_code_padded1(int, const char *, size_t);
void                    sc_print_sect_addr_padded(int, int, const char *, const char *, size_t);
void                    sc_print_string(const char *, Address, const char *, const char *,
                            Address, const char *, const char *, Address, const char *,
                            Address, const char *, int, int, size_t);
void                    sc_print_vector(const int *, Address, const char *, const char *,
                            Address, const char *, const char *, Address, const char *,
                            Address, const char *, int, int, size_t);
size_t                  sc_print_argv(const char * const *, Address, const char *, const char *,
                            Address, const char *, const char *, Address, const char *,
                            Address, const char *, int, int, size_t, int *, int *);

int                     how_many_pop(const char *);
int                     how_many_pop_before(const char *, const char *);
int                     how_many_pop_after(const char *, const char *);
char                    *get_reg(const char *, int);


/* xfunc */
void                    *xmalloc(size_t);
int                     xopen(const char *, int, mode_t);
void                    *xmmap(void *, size_t, int, int, int, off_t);
ssize_t                 xread(int, void *, size_t);
ssize_t                 xwrite(int, const void *, size_t);
int                     xclose(int);

/* x86-32bits */
extern t_asm            tab_x8632[];
void                    x8632_ropmaker(void);
void			x8632_makecode(t_list_inst *);
void                    x8632_makecode_importsc(t_list_inst *, int, char *);
void                    x8632_build_code(char *);

/* x86-64bits */
extern t_asm		tab_x8664[];
void                    x8664_ropmaker(void);
void                    x8664_makecode(t_list_inst *);
void                    x8664_makecode_importsc(t_list_inst *, int, char *);

#endif
