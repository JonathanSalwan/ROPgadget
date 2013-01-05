
all: nullable shared

nullable: nullable.c
	gcc -m64 -g -o $@ $< -static -fno-stack-protector

shared: main_linux.c
	gcc -m32 -o $@ $< -fno-stack-protector

clean:
	rm -f nullable shared
