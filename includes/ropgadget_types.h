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

#ifndef	 ROPgadget_types_H
#define	 ROPgadget_types_H

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

#endif
