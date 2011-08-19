/*
** RopGadget - Release v3.0
** Jonathan Salwan - http://shell-storm.org - http://twitter.com/shell_storm
** 2011-08-01
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
*/

#include "ropgadget.h"

#define NB_GADGET (sizeof(tab_x8632) / sizeof(tab_x8632[0])) - 2

/*
** If you want, you can add your gadgets in tab_x8632[]
** {FLAG, ADDR, INSTRUCTION, HEX INSTRUCTION}
*/
t_asm tab_x8632[] =
{
  {0, 0, "int $0x80", "\xcd\x80"},
  {0, 0, "sysenter", "\x0f\x34"},
  {0, 0, "call *%eax", "\xff\xd0"},
  {0, 0, "call *%ebx", "\xff\xd3"},
  {0, 0, "call *%ecx", "\xff\xd1"},
  {0, 0, "call *%edx", "\xff\xd2"},
  {0, 0, "call *%esi", "\xff\xd6"},
  {0, 0, "call *%edi", "\xff\xd7"},
  {0, 0, "jmp *%eax", "\xff\xe0"},
  {0, 0, "jmp *%ebx", "\xff\xe3"},
  {0, 0, "jmp *%ecx", "\xff\xe1"},
  {0, 0, "jmp *%edx", "\xff\xe2"},
  {0, 0, "jmp *%esi", "\xff\xe6"},
  {0, 0, "jmp *%edi", "\xff\xe7"},
  {0, 0, "pop %ebp | ret", "\x5d\xc3"},
  {0, 0, "pop %eax | ret", "\x58\xc3"},
  {0, 0, "pop %ebx | ret", "\x5b\xc3"},
  {0, 0, "pop %ecx | ret", "\x59\xc3"},
  {0, 0, "pop %edx | ret", "\x5a\xc3"},
  {0, 0, "pop %esi | ret", "\x5e\xc3"},
  {0, 0, "pop %edi | ret", "\x5f\xc3"},
  {0, 0, "pop %ebx | pop %ebp | ret", "\x5b\x5d\xc3"},
  {0, 0, "pop %eax | pop %ebx | pop %esi | pop %edi | ret", "\x58\x5b\x5e\x5f\xc3"},
  {0, 0, "pop %ebx | pop %esi | pop %ebp | ret", "\x5b\x5e\x5d\xc3"},
  {0, 0, "pop %ebx | pop %esi | pop %edi | pop %ebp | ret", "\x5b\x5e\x5f\x5d\xc3"},
  {0, 0, "pop %esi | pop %ebx | pop %edx | ret", "\x5e\x5b\x5a\xc3"},
  {0, 0, "pop %edx | pop %ecx | pop %ebx | ret", "\x5a\x59\x5b\xc3"},
  {0, 0, "xor %eax,%eax | ret", "\x31\xc0\xc3"},
  {0, 0, "xor %ebx,%ebx | ret", "\x31\xdb\xc3"},
  {0, 0, "xor %ecx,%ecx | ret", "\x31\xc9\xc3"},
  {0, 0, "xor %edx,%edx | ret", "\x31\xd2\xc3"},
  {0, 0, "xor %esi,%esi | ret", "\x31\xf6\xc3"},
  {0, 0, "xor %edi,%edi | ret", "\x31\xf7\xc3"},
  {0, 0, "xor %eax,%eax | pop %ebx | pop %ebp | ret", "\x31\xc0\x5b\x5d\xc3"},
  {0, 0, "xor %eax,%eax | pop %ebx | pop %esi | pop %edi | pop %ebp | ret", "\x31\xc0\x5b\x5e\x5f\x5d\xc3"},
  {0, 0, "xor %eax,%eax | pop %edi | ret", "\x31\xc0\x5f\xc3"},
  {0, 0, "xor %eax,%eax | pop %ebx | ret", "\x31\xc0\x5b\xc3"},
  {0, 0, "xor %eax,%eax | mov %esp, %ebp | pop %ebp | ret", "\x31\xc0\x89\xe5\x5d\xc3"},
  {0, 0, "inc %eax | ret", "\x40\xc3"},
  {0, 0, "inc %ebx | ret", "\x43\xc3"},
  {0, 0, "inc %ecx | ret", "\x41\xc3"},
  {0, 0, "inc %edx | ret", "\x42\xc3"},
  {0, 0, "inc %esi | ret", "\x46\xc3"},
  {0, 0, "inc %edi | ret", "\x47\xc3"},
  {0, 0, "inc %eax | pop %edi | pop %esi | ret", "\x40\x5f\x5e\xc3"},
  {0, 0, "inc %eax | pop %edi | ret", "\x40\x5f\xc3"},
  {0, 0, "inc %eax | inc %eax | inc %eax | ret", "\x40\x40\x40\xc3"},
  {0, 0, "inc %eax | inc %eax | ret", "\x40\x40\xc3"},
  {0, 0, "sub $0x1,%eax | pop %ebx | pop %esi | pop %ebp | ret", "\x83\xe8\x01\x5b\x5e\x5d\xc3"},
  {0, 0, "sub %ebx,%eax | pop %ebx | pop %esi | pop %edi | pop %ebp | ret", "\x29\xd8\x5b\x5e\x5f\x5d\xc3"},
  {0, 0, "sub $0x1,%eax | pop %ebp | ret", "\x89\xe8\x01\x5d\xc3"},
  {0, 0, "sub $0x1,%eax | ret", "\x83\xe8\x01\xc3"},
  {0, 0, "sub $0x1,%ebx | ret", "\x83\xeb\x01\xc3"},
  {0, 0, "sub $0x1,%ecx | ret", "\x83\xe9\x01\xc3"},
  {0, 0, "sub $0x1,%edx | ret", "\x83\xea\x01\xc3"},
  {0, 0, "sub $0x1,%esi | ret", "\x83\xee\x01\xc3"},
  {0, 0, "sub $0x1,%edi | ret", "\x83\xef\x01\xc3"},
  {0, 0, "add %ebx,%eax | pop %ebx | pop %ebp | ret", "\x01\xd8\x5b\x5d\xc3"},
  {0, 0, "xchg %esp,%eax | ret", "\x94\xc3"},
  {0, 0, "mov %ebx,%eax | pop %ebx | pop %ebp | ret", "\x89\xd8\x5b\x5d\xc3"},
  {0, 0, "mov %edx,%eax | pop %ebx | pop %esi | pop %edi | pop %ebp | ret", "\x89\xd0\x5b\x5e\x5f\x5d\xc3"},
  {0, 0, "mov %edi,%eax | pop %ebx | pop %esi | pop %edi | pop %ebp | ret", "\x89\xf8\x5b\x5e\x5f\x5d\xc3"},
  {0, 0, "mov %ebx,%eax | pop %ebx | pop %esi | pop %edi | pop %ebp | ret", "\x89\xd8\x5b\x5e\x5f\x5d\xc3"},
  {0, 0, "mov %esi,%eax | pop %ebx | pop %esi | pop %edi | pop %ebp | ret", "\x89\xf0\x5b\x5e\x5f\x5d\xc3"},
  {0, 0, "mov %ecx,%eax | pop %ebx | pop %esi | pop %edi | pop %ebp | ret", "\x89\xc8\x5b\x5e\x5f\x5d\xc3"},
  {0, 0, "mov %ebx,%eax | pop %ebx | pop %esi | pop %ebp | ret", "\x89\xd8\x5b\x5e\x5d\xc3"},
  {0, 0, "mov %ebp,%esp | pop %ebp | ret", "\x89\xec\x5d\xc3"},
  {0, 0, "mov %esp,%eax | ret", "\x89\xe0\xc3"},
  {0, 0, "mov %esp,%ebx | ret", "\x89\xe3\xc3"},
  {0, 0, "mov %esp,%ecx | ret", "\x89\xe1\xc3"},
  {0, 0, "mov %esp,%edx | ret", "\x89\xe2\xc3"},
  {0, 0, "mov %esp,%ebp | ret", "\x89\xe5\xc3"},
  {0, 0, "mov %eax,%ebx | ret", "\x89\xc3\xc3"},
  {0, 0, "mov %eax,%ecx | ret", "\x89\xc1\xc3"},
  {0, 0, "mov %eax,%edx | ret", "\x89\xc2\xc3"},
  {0, 0, "mov %eax,%esi | ret", "\x89\xc6\xc3"},
  {0, 0, "mov %eax,%edi | ret", "\x89\xc7\xc3"},
  {0, 0, "mov %ebx,%eax | ret", "\x89\xd8\xc3"},
  {0, 0, "mov %ebx,%ecx | ret", "\x89\xd9\xc3"},
  {0, 0, "mov %ebx,%edx | ret", "\x89\xda\xc3"},
  {0, 0, "mov %ebx,%esi | ret", "\x89\xde\xc3"},
  {0, 0, "mov %ebx,%edi | ret", "\x89\xdf\xc3"},
  {0, 0, "mov %ecx,%eax | ret", "\x89\xc8\xc3"},
  {0, 0, "mov %ecx,%ebx | ret", "\x89\xcb\xc3"},
  {0, 0, "mov %ecx,%edx | ret", "\x89\xca\xc3"},
  {0, 0, "mov %ecx,%esi | ret", "\x89\xce\xc3"},
  {0, 0, "mov %ecx,%edi | ret", "\x89\xcf\xc3"},
  {0, 0, "mov %edx,%eax | ret", "\x89\xd0\xc3"},
  {0, 0, "mov %edx,%ebx | ret", "\x89\xd3\xc3"},
  {0, 0, "mov %edx,%ecx | ret", "\x89\xd1\xc3"},
  {0, 0, "mov %edx,%esi | ret", "\x89\xd6\xc3"},
  {0, 0, "mov %edx,%edi | ret", "\x89\xd7\xc3"},
  {0, 0, "mov %esi,%eax | ret", "\x89\xf0\xc3"},
  {0, 0, "mov %esi,%ebx | ret", "\x89\xf3\xc3"},
  {0, 0, "mov %esi,%ecx | ret", "\x89\xf1\xc3"},
  {0, 0, "mov %esi,%edx | ret", "\x89\xf2\xc3"},
  {0, 0, "mov %esi,%edi | ret", "\x89\xf7\xc3"},
  {0, 0, "mov %edi,%eax | ret", "\x89\xf8\xc3"},
  {0, 0, "mov %edi,%ebx | ret", "\x89\xfb\xc3"},
  {0, 0, "mov %edi,%ecx | ret", "\x89\xf9\xc3"},
  {0, 0, "mov %edi,%edx | ret", "\x89\xfa\xc3"},
  {0, 0, "mov %edi,%esi | ret", "\x89\xfe\xc3"},
  {0, 0, "mov %esp,%eax | pop %ebp | ret", "\x89\xe0\x5d\xc3"},
  {0, 0, "mov %esp,%ebx | pop %ebp | ret", "\x89\xe3\x5d\xc3"},
  {0, 0, "mov %esp,%ecx | pop %ebp | ret", "\x89\xe1\x5d\xc3"},
  {0, 0, "mov %esp,%edx | pop %ebp | ret", "\x89\xe2\x5d\xc3"},
  {0, 0, "mov %eax,%ebx | pop %ebp | ret", "\x89\xc3\x5d\xc3"},
  {0, 0, "mov %eax,%ecx | pop %ebp | ret", "\x89\xc1\x5d\xc3"},
  {0, 0, "mov %eax,%edx | pop %ebp | ret", "\x89\xc2\x5d\xc3"},
  {0, 0, "mov %eax,%esi | pop %ebp | ret", "\x89\xc6\x5d\xc3"},
  {0, 0, "mov %eax,%edi | pop %ebp | ret", "\x89\xc7\x5d\xc3"},
  {0, 0, "mov %ebx,%eax | pop %ebp | ret", "\x89\xd8\x5d\xc3"},
  {0, 0, "mov %ebx,%ecx | pop %ebp | ret", "\x89\xd9\x5d\xc3"},
  {0, 0, "mov %ebx,%edx | pop %ebp | ret", "\x89\xda\x5d\xc3"},
  {0, 0, "mov %ebx,%esi | pop %ebp | ret", "\x89\xde\x5d\xc3"},
  {0, 0, "mov %ebx,%edi | pop %ebp | ret", "\x89\xdf\x5d\xc3"},
  {0, 0, "mov %ecx,%eax | pop %ebp | ret", "\x89\xc8\x5d\xc3"},
  {0, 0, "mov %ecx,%ebx | pop %ebp | ret", "\x89\xcb\x5d\xc3"},
  {0, 0, "mov %ecx,%edx | pop %ebp | ret", "\x89\xca\x5d\xc3"},
  {0, 0, "mov %ecx,%esi | pop %ebp | ret", "\x89\xce\x5d\xc3"},
  {0, 0, "mov %ecx,%edi | pop %ebp | ret", "\x89\xcf\x5d\xc3"},
  {0, 0, "mov %edx,%eax | pop %ebp | ret", "\x89\xd0\x5d\xc3"},
  {0, 0, "mov %edx,%ebx | pop %ebp | ret", "\x89\xd3\x5d\xc3"},
  {0, 0, "mov %edx,%ecx | pop %ebp | ret", "\x89\xd1\x5d\xc3"},
  {0, 0, "mov %edx,%esi | pop %ebp | ret", "\x89\xd6\x5d\xc3"},
  {0, 0, "mov %edx,%edi | pop %ebp | ret", "\x89\xd7\x5d\xc3"},
  {0, 0, "mov %esi,%eax | pop %ebp | ret", "\x89\xf0\x5d\xc3"},
  {0, 0, "mov %esi,%ebx | pop %ebp | ret", "\x89\xf3\x5d\xc3"},
  {0, 0, "mov %esi,%ecx | pop %ebp | ret", "\x89\xf1\x5d\xc3"},
  {0, 0, "mov %esi,%edx | pop %ebp | ret", "\x89\xf2\x5d\xc3"},
  {0, 0, "mov %esi,%edi | pop %ebp | ret", "\x89\xf7\x5d\xc3"},
  {0, 0, "mov %edi,%eax | pop %ebp | ret", "\x89\xf8\x5d\xc3"},
  {0, 0, "mov %edi,%ebx | pop %ebp | ret", "\x89\xfb\x5d\xc3"},
  {0, 0, "mov %edi,%ecx | pop %ebp | ret", "\x89\xf9\x5d\xc3"},
  {0, 0, "mov %edi,%edx | pop %ebp | ret", "\x89\xfa\x5d\xc3"},
  {0, 0, "mov %edi,%esi | pop %ebp | ret", "\x89\xfe\x5d\xc3"},
  {0, 0, "mov %eax,(%edx) | ret", "\x89\x02\xc3"},
  {0, 0, "mov %eax,(%ebx) | ret", "\x89\x03\xc3"},
  {0, 0, "mov %eax,(%ecx) | ret", "\x89\x01\xc3"},
  {0, 0, "mov %eax,(%esi) | ret", "\x89\x06\xc3"},
  {0, 0, "mov %eax,(%edi) | ret", "\x89\x07\xc3"},
  {0, 0, "mov %ebx,(%eax) | ret", "\x89\x18\xc3"},
  {0, 0, "mov %ebx,(%ecx) | ret", "\x89\x19\xc3"},
  {0, 0, "mov %ebx,(%edx) | ret", "\x89\x1a\xc3"},
  {0, 0, "mov %ebx,(%esi) | ret", "\x89\x1e\xc3"},
  {0, 0, "mov %ebx,(%edi) | ret", "\x89\x1f\xc3"},
  {0, 0, "mov %ecx,(%eax) | ret", "\x89\x08\xc3"},
  {0, 0, "mov %ecx,(%ebx) | ret", "\x89\x0b\xc3"},
  {0, 0, "mov %ecx,(%edx) | ret", "\x89\x0a\xc3"},
  {0, 0, "mov %ecx,(%esi) | ret", "\x89\x0e\xc3"},
  {0, 0, "mov %ecx,(%edi) | ret", "\x89\x0f\xc3"},
  {0, 0, "mov %edx,(%eax) | ret", "\x89\x10\xc3"},
  {0, 0, "mov %edx,(%ebx) | ret", "\x89\x13\xc3"},
  {0, 0, "mov %edx,(%ecx) | ret", "\x89\x11\xc3"},
  {0, 0, "mov %edx,(%esi) | ret", "\x89\x16\xc3"},
  {0, 0, "mov %edx,(%edi) | ret", "\x89\x17\xc3"},
  {0, 0, "mov %eax,(%edx) | pop %ebp | ret", "\x89\x02\x5d\xc3"},
  {0, 0, "mov %eax,(%ebx) | pop %ebp | ret", "\x89\x03\x5d\xc3"},
  {0, 0, "mov %eax,(%ecx) | pop %ebp | ret", "\x89\x01\x5d\xc3"},
  {0, 0, "mov %eax,(%esi) | pop %ebp | ret", "\x89\x06\x5d\xc3"},
  {0, 0, "mov %eax,(%edi) | pop %ebp | ret", "\x89\x07\x5d\xc3"},
  {0, 0, "mov %ebx,(%eax) | pop %ebp | ret", "\x89\x18\x5d\xc3"},
  {0, 0, "mov %ebx,(%ecx) | pop %ebp | ret", "\x89\x19\x5d\xc3"},
  {0, 0, "mov %ebx,(%edx) | pop %ebp | ret", "\x89\x1a\x5d\xc3"},
  {0, 0, "mov %ebx,(%esi) | pop %ebp | ret", "\x89\x1e\x5d\xc3"},
  {0, 0, "mov %ebx,(%edi) | pop %ebp | ret", "\x89\x1f\x5d\xc3"},
  {0, 0, "mov %ecx,(%eax) | pop %ebp | ret", "\x89\x08\x5d\xc3"},
  {0, 0, "mov %ecx,(%ebx) | pop %ebp | ret", "\x89\x0b\x5d\xc3"},
  {0, 0, "mov %ecx,(%edx) | pop %ebp | ret", "\x89\x0a\x5d\xc3"},
  {0, 0, "mov %ecx,(%esi) | pop %ebp | ret", "\x89\x0e\x5d\xc3"},
  {0, 0, "mov %ecx,(%edi) | pop %ebp | ret", "\x89\x0f\x5d\xc3"},
  {0, 0, "mov %edx,(%eax) | pop %ebp | ret", "\x89\x10\x5d\xc3"},
  {0, 0, "mov %edx,(%ebx) | pop %ebp | ret", "\x89\x13\x5d\xc3"},
  {0, 0, "mov %edx,(%ecx) | pop %ebp | ret", "\x89\x11\x5d\xc3"},
  {0, 0, "mov %edx,(%esi) | pop %ebp | ret", "\x89\x16\x5d\xc3"},
  {0, 0, "mov %edx,(%edi) | pop %ebp | ret", "\x89\x17\x5d\xc3"},
  {0, 0, "mov %edx,%eax | pop %ebx | pop %esi | pop %edi | pop %ebp | ret", "\x89\xd0\x5b\x5e\x5f\x5d\xc3"},
  {0, 0, "mov %eax,%edi | mov %edi,%eax | pop %edi | pop %ebp | ret", "\x89\xc7\x89\xf8\x5f\x5d\xc3"},
  {0, 0, "mov (%edx),%eax | mov (%esp),%ebx | mov %ebp,%esp | pop %ebp | ret", "\x03\x02\x8b\x1c\x24\x89\xec\x5d\xc3"},
  {0, 0, "mov %eax,(%edi) | pop %eax | pop %ebx | pop %esi | pop %edi | ret", "\x89\x07\x58\x5b\x5e\x5f\xc3"},
  {0, 0, "mov %ebx,(%edi) | pop %ebx | pop %esi | pop %edi | ret", "\x89\x1f\x5b\x5e\x5f\xc3"},
  {0, 0, "mov %eax,(%ecx) | mov %ebx,%eax | pop %ebx | pop %ebp | ret", "\x89\x01\x89\xd8\x5b\x5d\xc3"},
  {0, 0, "mov %ebp,%eax | pop %ebx | pop %esi | pop %edi | pop %ebp | ret", "\x89\xe8\x5b\x5e\x5f\x5d\xc3"},
  {0, 0, "mov %ebx,%eax | pop %ebx | pop %esi | pop %edi | ret", "\x89\xd8\x5b\x5e\x5f\xc3"},
  {0, 0, "mov %edi,%eax | pop %ebx | pop %esi | pop %edi | ret", "\x89\xf8\x5b\x5e\x5f\xc3"},
  {0, 0, "mov %ebx,%eax | pop %ebx | ret", "\x89\xd8\x5b\xc3"},
  {0, 0, NULL, NULL}
};

void gadget_x8632(unsigned char *data, unsigned int cpt, Elf32_Addr offset, int i, t_maps_exec *maps_exec)
{
  if(!strncmp((const char *)data, tab_x8632[i].value, strlen(tab_x8632[i].value))
     && !check_exec_maps(maps_exec, (Elf32_Addr)(cpt + offset)))
    {
      fprintf(stdout, "%s0x%.8x%s: %s%s%s\n", RED, (cpt + offset), ENDC, GREEN, tab_x8632[i].instruction, ENDC);
      tab_x8632[i].flag = 1;
      tab_x8632[i].addr = (Elf32_Addr)(cpt + offset);
    }
}

void x8632(unsigned char *data, unsigned int size_data, t_maps_exec *maps_exec)
{
  int i              = 0;
  unsigned int cpt   = 0;

  pGadgets = tab_x8632;
  while(cpt < size_data)
    {
      i = 0;
      while (i <= (int)NB_GADGET)
        {
          if (pGadgets[i].flag != 1)
            gadget_x8632(data, cpt, (pElf32_Phdr->p_vaddr - pElf32_Phdr->p_offset), i, maps_exec);
          i++;
        }
      cpt++;
      data++;
    }
  how_many_found();
}
