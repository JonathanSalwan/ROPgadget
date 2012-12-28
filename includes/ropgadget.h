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

#define TRUE              1
#define FALSE             0

/* type definitions for easing transition */
typedef Elf64_Addr Address;
typedef Elf64_Off Offset;
typedef uint64_t Size;
#define ADDR_FORMAT "0x%.*lx"
#define SIZE_FORMAT "0x%.*lu"

#define ADDR_WIDTH ((containerType == CONTAINER_ELF32)?8:16)
#define SIZE_WIDTH ADDR_WIDTH

/* does something to the phdr/header struct with a given type, based on 32 or 64 bits */
/* Joshua 7:20 - Achan replied, "It is true! I have sinned against the LORD, the God of Israel." */
#define PHDR(X, t) (containerType == CONTAINER_ELF32?((t)(pElf32_Phdr X)):((t)(pElf64_Phdr X)))
#define EHDR(X, t) (containerType == CONTAINER_ELF32?((t)(pElf32_Header X)):((t)(pElf64_Header X)))

/* These are for the Reverse Polish Notation used to define shellcodes (CR = combo ropmaker) */
#define CR_AND "&"
#define CR_OR "|"
#define CR_OPT "?"

/* Simple macro for checking which syntax to display an asm in */
#define DISPLAY_SYNTAX(a) ((syntaxins==INTEL)?((a)->instruction_intel):((a)->instruction))

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
  t_asm                 *gadget;
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
  size_t cpt;
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

typedef struct s_gadget
{
  char *inst;
  t_asm *gadget;
} t_gadget;

/* struct for passing around a set of instructions that can be used to write
** arbitrary data in the memory space */
typedef struct s_rop_writer
{
  /* Gadget that pops an address from the stack into the target register */
  t_gadget *pop_target;

  /* Gadget that pops from the stack some data to be moved to the target */
  t_gadget *pop_data;

  /* Gadget that moves the data in data reg to the location in target reg */
  t_gadget *mov;

  /* Gadget that sets the target register to all zeros */
  t_gadget *zero_data;
} t_rop_writer;

/* struct for passing arguments to importsc writer */
typedef struct s_importsc_writer
{
  t_gadget *pop_gad;
  t_gadget *mov_gad2;
  t_gadget *mov_gad3;
  t_gadget *mov_gad4;
} t_importsc_writer;

/* globals vars */
Elf32_Ehdr          	*pElf32_Header;
Elf64_Ehdr          	*pElf64_Header;

Elf32_Phdr *pElf32_Phdr;
Elf64_Phdr *pElf64_Phdr;

Address  		Addr_sData;
Address              Addr_sGot;

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
void           		search_gadgets(unsigned char *, size_t);

/* maps */
void                    free_add_map(t_map *);
t_map   		*return_map(int);
int			check_maps(t_map *, Address);
void                    map_parse(char *);
size_t                  set_cpt_if_mapmode(size_t);
size_t                  check_end_mapmode(size_t);

/* sections */
void                    save_section(void);

/* stringmode */
unsigned char           *real_string_stringmode(char *, unsigned char *);
void                    print_real_string(unsigned char *str);

/* filemode */
void                    process_filemode(char *);

/* word mode */
t_word_linked           *add_element_word(t_word_linked *, char *);
int 			filter(char *, t_filter_mode *);

/* opcode/importsc */
void                    make_opcode(char *, t_opcode *op);
void                    save_octet(unsigned char *, Address);
void 			print_opcode(void);
int                     check_opcode_was_found(void);

/* gadgets */
void 			find_all_gadgets(unsigned char *, size_t, t_map *, t_map *, t_asm *, unsigned int *, unsigned int *);

/* argv */
char                    **get_argv(void);
void                    free_argv(char **argv);

/* varop */
int 			check_interrogation(const char *);
char 			*ret_instruction(const unsigned char *, const char *, const char *, size_t);
int			check_if_varop_was_printed(const char *, const t_list_inst *pVarop);
char                    getreg(const char *, int i);
char                    *get_reg(const char *, int);
t_list_inst             *add_element(t_list_inst *, char *, t_asm *);
void 			free_list_inst(t_list_inst *);

/* ropmaker */
t_asm  	                *search_instruction(t_asm *, char *);
int                     match(const char *, const char *);
int                     match2(const unsigned char *, const unsigned char *, size_t);

/* combo_ropmaker */
int                     combo_ropmaker(char **, t_asm *, t_gadget **);

/* makecode: Mid-level payload generation */
void                    sc_print_sect_addr_pop(const t_gadget *, int, int, size_t);
void                    sc_print_addr_pop(const t_gadget *, Address, const char *, size_t);
void                    sc_print_str_pop(const t_gadget *, const char *, size_t);
void                    sc_print_solo_inst(const t_gadget *, size_t);

/* makecode: High-level payload generation */
void                    sc_print_string(const char *, const t_rop_writer *, int, int, size_t);
void                    sc_print_vector(const int *, const t_rop_writer *, int, int, size_t);
size_t                  sc_print_argv(const char * const *, const t_rop_writer *, int, int, size_t, int *, int *);
int                     sc_print_gotwrite(const t_importsc_writer *, size_t bytes);

/* xfunc */
void                    *xmalloc(size_t);
int                     xopen(const char *, int, mode_t);
void                    *xmmap(void *, size_t, int, int, int, off_t);
ssize_t                 xread(int, void *, size_t);
ssize_t                 xwrite(int, const void *, size_t);
int                     xclose(int);

/* common makecodes */
void                    x86_makecode_importsc(t_gadget *, size_t);
void                    x86_makecode(t_gadget *, size_t);
void                    x86_ropmaker(size_t);
void                    x86_build_code(char *);

/* x86-32bits */
extern t_asm            tab_x8632[];
extern char             *tab_x8632_ropmaker[];

/* x86-64bits */
extern t_asm		tab_x8664[];
extern char             *tab_x8664_ropmaker[];

#endif
