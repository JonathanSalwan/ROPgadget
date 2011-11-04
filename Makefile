##
## RopGadget - Dev v3.3
## Jonathan Salwan - http://twitter.com/JonathanSalwan
## http://shell-storm.org
## 2011-10-18
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
##

DEBUG   = no
RM      = rm -f
INCLUDE = ./includes
SRC_DIR = ./src
NAME    = ROPgadget

ifeq ($(DEBUG),yes)
    CFLAGS   	= -g3 -ggdb -Wextra -Wall -D _BSD_SOURCE -I$(INCLUDE)
    CC 		= clang
else
    CFLAGS    	= -W -Wall -ansi -pedantic -D _BSD_SOURCE -I$(INCLUDE)
    CC 		= gcc
endif

SRC     = 	$(SRC_DIR)/main.c \
          	$(SRC_DIR)/syntax.c \
          	$(SRC_DIR)/display_data.c \
          	$(SRC_DIR)/search_gadgets.c \
	  	$(SRC_DIR)/search_opcode.c \
          	$(SRC_DIR)/gadget_x8632.c \
          	$(SRC_DIR)/check_elf_format.c \
          	$(SRC_DIR)/check_arch_supported.c \
          	$(SRC_DIR)/save_bin_data.c \
		$(SRC_DIR)/save_octet.c \
	  	$(SRC_DIR)/get_flags.c \
	  	$(SRC_DIR)/get_seg.c \
          	$(SRC_DIR)/check_exec_maps.c \
		$(SRC_DIR)/check_read_maps.c \
          	$(SRC_DIR)/ropmaker.c \
	  	$(SRC_DIR)/makecode.c \
		$(SRC_DIR)/return_maps_exec.c \
		$(SRC_DIR)/return_maps_read.c \
		$(SRC_DIR)/makecode_importsc.c \
		$(SRC_DIR)/real_string_stringmode.c \
	 	$(SRC_DIR)/how_many_found.c \
          	$(SRC_DIR)/combo_ropmaker1.c \
          	$(SRC_DIR)/combo_ropmaker2.c \
		$(SRC_DIR)/combo_ropmaker_importsc.c \
		$(SRC_DIR)/check_file_mode.c \
		$(SRC_DIR)/check_v_mode.c \
		$(SRC_DIR)/check_g_mode.c \
	  	$(SRC_DIR)/check_bind_mode.c \
	  	$(SRC_DIR)/check_filter_mode.c \
	  	$(SRC_DIR)/check_only_mode.c \
	  	$(SRC_DIR)/check_opcode_mode.c \
	  	$(SRC_DIR)/check_string_mode.c \
	  	$(SRC_DIR)/check_asm_mode.c \
		$(SRC_DIR)/check_importsc_mode.c \
		$(SRC_DIR)/check_elfheader_mode.c \
		$(SRC_DIR)/check_progheader_mode.c \
		$(SRC_DIR)/check_sectheader_mode.c \
		$(SRC_DIR)/check_allheader_mode.c \
		$(SRC_DIR)/check_syntax_mode.c \
		$(SRC_DIR)/check_limit_mode.c \
		$(SRC_DIR)/check_map_mode.c \
		$(SRC_DIR)/check_symtab_mode.c \
		$(SRC_DIR)/check_option.c \
	  	$(SRC_DIR)/no_filtered.c \
	  	$(SRC_DIR)/varop.c \
	  	$(SRC_DIR)/onlymode.c \
		$(SRC_DIR)/save_section.c \
		$(SRC_DIR)/save_symbols.c \
		$(SRC_DIR)/get_addr_section.c \
		$(SRC_DIR)/get_size_section.c \
		$(SRC_DIR)/get_entsize_section.c \
		$(SRC_DIR)/get_offset_section.c \
		$(SRC_DIR)/xfunc.c


OBJ      = $(SRC:.c=.o)

all:     $(NAME)

$(NAME): $(OBJ)
	 $(CC) $(CFLAGS) -o $(NAME) $(OBJ)

install:
	 install -D -m 755 ./$(NAME) /usr/bin/$(NAME)

clean:
	 $(RM) $(OBJ)

fclean:  clean
	 $(RM) $(NAME)

re:	 fclean all

.PHONY:  re fclean clean install all
