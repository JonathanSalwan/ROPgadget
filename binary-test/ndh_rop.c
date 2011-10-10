/*
** ndh_rop.c for binary-test in /home/jonathan/all/prog/c/ROPgadget-v3.0/binary-test
** 
** Made by jonathan salwan
** Login   <salwan_j@epitech.net>
** 
** Started on  Thu Jun 04 02:41:58 2009 jonathan salwan
** Last update Thu Jun 04 02:41:58 2009 jonathan salwan
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void rop()
{
        __asm("ret");

        __asm("pop %ebx");
        __asm("ret");

        __asm("nop");
        __asm("movl %esi, %edx");
        __asm("pop %esi");
        __asm("inc %esi");
        __asm("ret");

        __asm("xor %eax, %eax");
        __asm("inc %eax");
        __asm("ret");

        __asm("int $0x80");
        __asm("sysenter");
}

void vuln(char *buff)
{
        char tmp[8] = {'\0'};

        strcpy(tmp, buff);
        printf("-> %s\n", tmp);
}

int main(int argc, char *argv[])
{
        if(argc != 2) {
                printf("%s <arg>\n", argv[0]);
                exit(0);
        }
        printf("ROP me if you can :]\n");

        vuln(argv[1]);
        return 0;
}
