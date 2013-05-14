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

#ifndef	 ROPgadget_H
#define	 ROPgadget_H

#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <wchar.h>
#include <ctype.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <wait.h>
#include <fcntl.h>
#include <elf.h>
#include <stdio.h>

#define ROPGADGET_VERSION "Ropgadget v4.0.2"

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
#define ADDR_FORMAT "0x%.*"PRIx64
#define SIZE_FORMAT "%.*"PRIu64

#define ADDR_WIDTH ((binary->processor == PROCESSOR_X8632)?8:16)
#define SIZE_WIDTH ADDR_WIDTH

/* These are for the Reverse Polish Notation used to define shellcodes (CR = combo ropmaker) */
#define CR_AND "&"
#define CR_OR "|"
#define CR_OPT "?"

/* Simple macro for checking which syntax to display an asm in */
#define DISPLAY_SYNTAX(a) ((syntaxins==INTEL)?((a)->instruction_intel):((a)->instruction))

/* output control marcros */
/* user */
#define uprintf(...) fprintf(stderr, __VA_ARGS__)
/* output / payload */
#define oprintf(...) fprintf(stdout, __VA_ARGS__)
/* error */
#define eprintf(...) fprintf(stderr, __VA_ARGS__)
/* help */
#define hprintf(...) fprintf(stdout, __VA_ARGS__)


typedef enum {
  CONTAINER_ELF32,
  CONTAINER_ELF64,
  CONTAINER_PE
} e_container;

typedef enum {
  PROCESSOR_X8632,
  PROCESSOR_X8664
} e_processor;

typedef enum {
  OBJECT_EXECUTABLE,
  OBJECT_SHARED
} e_object;

typedef enum {
  ABI_LINUX,
  ABI_WINNT
} e_abi;

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
  Size                  size;
  Address               offset;
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

/* -opcode and -importsc */
typedef struct s_opcode
{
  unsigned char *opcode;
  size_t size;
  int  flag;
} t_opcode;

/* -string and -asm options*/
typedef struct s_stringmode
{
  char *string;
  int  flag;
} t_stringmode;

/* -syntax */
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
  size_t value;
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

/* Dependencies for elf files (shared objects) */
typedef struct s_depend
{
  char *name;
  struct s_depend *next;
} t_depend;

enum e_where {
  BEFORE,
  AFTER,
  TOTAL
};

/* Represents an entire binary loaded into memory */
typedef struct s_binary
{
  char *file;
  e_container container;
  e_processor processor;
  e_object object;
  e_abi abi;
  size_t size;
  unsigned char *data;

  t_map *maps_exec;
  t_map *maps_read;

  /* This points to the largest writable segement for data for syscalls */
  Address writable_offset;
  Size writable_size;

  /* This points to the largest writable exec segment for use when making sc */
  Address writable_exec_offset;
  Size writable_exec_size;

  /* this points to the first exec segment for use when parsing asm */
  Address exec_offset;
  Size exec_size;

  t_depend *depends;

  /* private (used by elf parsing) */
  unsigned char *phdr;
  Offset load_diff;
  int load_diff_set;
} t_binary;

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

/* globals vars */
t_binary                *binary;

/* flag options */
t_opcode                opcode_mode;	/*  -opcode 	                  */
t_stringmode            stringmode;     /*  -string                       */
t_stringmode            asm_mode;	/*  -asm 	                  */
t_opcode                importsc_mode;	/*  -importsc 	                  */
t_bind_mode             bind_mode;	/*  -bind & -port                 */
t_filter_mode           filter_mode;	/*  -filter 	                  */
t_filter_mode           only_mode;	/*  -only 	                  */
t_limitmode             limitmode;      /*  -limit                        */
t_mapmode               mapmode;        /*  -map                          */
e_syntaxcode            syntaxcode;     /*  -pysyn -csyn -phpsyn -perlsyn */
e_syntax                syntaxins;      /*  -intel -att                   */
char                    **target_argv;  /*  non-default target            */

/* color variables */
char                    *BLUE;
char                    *RED;
char                    *YELLOW;
char                    *GREEN;
char                    *ENDC;

/* core */
void           		syntax(char *);
void                    version(void);
void           		search_gadgets(t_binary *);

/* maps */
void                    map_parse(char *);

/* stringmode */
unsigned char           *real_string_stringmode(char *, unsigned char *);
void                    print_real_string(unsigned char *str);

/* filemode */
t_binary                *process_binary(char *);
void                    free_binary(t_binary *);
t_map                   *add_map(t_map *, Address, Address, Size);
t_depend                *add_dep(t_depend *, char *);
int                     process_elf(t_binary *);
int                     process_pe(t_binary *, int);

/* word mode */
t_word_linked           *add_element_word(t_word_linked *, char *);
int 			filter(char *, t_filter_mode *);

/* opcode/importsc */
void                    make_opcode(char *, t_opcode *op);
void 			print_opcode(void);

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

/* pop info */
#define how_many_pop(g) how_many_pop_x(g, NULL, TOTAL)
#define how_many_pop_before(g, i) how_many_pop_x(g, i, BEFORE)
#define how_many_pop_after(g, i) how_many_pop_x(g, i, AFTER)
size_t how_many_pop_x(const char *gadget, const char *pop_reg, enum e_where w);



/* combo_ropmaker */
int                     combo_ropmaker(char **, t_asm *, t_gadget **);
void                    sc_print_pre_init(void);
void                    sc_print_init(void);
void                    sc_print_end(void);
void                    sc_print_comment(const char *);

void                    sc_print_sect_addr(int offset, int data, size_t bytes);

/* makecode: Mid-level payload generation */
void                    sc_print_sect_addr_pop(const t_gadget *, int, int, size_t);
void                    sc_print_addr_pop(const t_gadget *, Address, const char *, size_t);
void                    sc_print_raw_pop(const t_gadget *, const char *, size_t, size_t);
void                    sc_print_str_pop(const t_gadget *, const char *, size_t);
void                    sc_print_solo_inst(const t_gadget *, size_t);

/* makecode: High-level payload generation */
void                    sc_print_raw_string(const char *, size_t, const t_rop_writer *, int, int, size_t);
void                    sc_print_string(const char *, const t_rop_writer *, int, int, size_t);
void                    sc_print_vector(const int *, const t_rop_writer *, int, int, size_t);
size_t                  sc_print_argv(const char * const *, const t_rop_writer *, int, int, size_t, int *, int *);

/* xfunc */
void                    *xmalloc(size_t);
int                     xopen(const char *, int, mode_t);
void                    *xmmap(void *, size_t, int, int, int, off_t);
ssize_t                 xread(int, void *, size_t);
ssize_t                 xwrite(int, const void *, size_t);
char                    *xstrdup(const char *);
int                     xclose(int);

/* common makecodes */
void                    x86_makecode_importsc(t_gadget *, size_t);
void                    x86_makecode(t_gadget *, size_t);
void                    x86_ropmaker(size_t);
void                    x86_build_code(char *, e_processor);

/* x86-32bits */
extern t_asm            tab_x8632[];
extern char             *tab_x8632_ropmaker[];
extern char             *tab_x8632_importsc[];

/* x86-64bits */
extern t_asm		tab_x8664[];
extern char             *tab_x8664_ropmaker[];
extern char             *tab_x8664_importsc[];

#endif
