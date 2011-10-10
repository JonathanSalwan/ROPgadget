##
## RopGadget - Release v3.2
## Jonathan Salwan - http://twitter.com/JonathanSalwan
## http://shell-storm.org
## 2011-10-10
##
## Redistribution and use in source and binary forms, with or without
## modification, are permitted provided that the following conditions
## are met:
## 1. Redistributions of source code must retain the above copyright
##    notice, this list of conditions and the following disclaimer.
## 2. Redistributions in binary form must reproduce the above copyright
##    notice, this list of conditions and the following disclaimer in the
##    documentation and/or other materials provided with the distribution.
##

DEBUG   = no
RM      = rm -f
INCLUDE = ./includes
SRC_DIR = ./src
NAME    = ROPgadget

ifeq ($(DEBUG),yes)
    CFLAGS    	=  -g3 -ggdb -Wextra -Wall -D _BSD_SOURCE -I$(INCLUDE)
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
	  	$(SRC_DIR)/display_version.c \
	  	$(SRC_DIR)/get_flags.c \
	  	$(SRC_DIR)/get_seg.c \
	  	$(SRC_DIR)/display_info_header.c \
          	$(SRC_DIR)/check_exec_maps.c \
          	$(SRC_DIR)/ropmaker.c \
	  	$(SRC_DIR)/makecode.c \
		$(SRC_DIR)/makecode_importsc.c \
	 	$(SRC_DIR)/how_many_found.c \
          	$(SRC_DIR)/combo_ropmaker1.c \
          	$(SRC_DIR)/combo_ropmaker2.c \
		$(SRC_DIR)/combo_ropmaker_importsc.c \
	  	$(SRC_DIR)/check_bind_mode.c \
	  	$(SRC_DIR)/check_filter_mode.c \
	  	$(SRC_DIR)/check_only_mode.c \
	  	$(SRC_DIR)/check_opcode_mode.c \
		$(SRC_DIR)/check_importsc_mode.c \
	  	$(SRC_DIR)/no_filtered.c \
	  	$(SRC_DIR)/varop.c \
	  	$(SRC_DIR)/onlymode.c

OBJ      = $(SRC:.c=.o)

all:     $(NAME)

$(NAME): $(OBJ)
	 $(CC) $(CFLAGS) -o $(NAME) $(OBJ)

install:
	 cp ./$(NAME) /usr/bin/$(NAME)

clean:
	 $(RM) $(OBJ)

fclean:  clean
	 $(RM) $(NAME)

re:	 fclean all

.PHONY:  re fclean clean install all
