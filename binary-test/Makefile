OBJS = nullable shared win32-shared

all: $(OBJS)

nullable: nullable.c
	gcc -m64 -g -o $@ $< -static -fno-stack-protector

shared: main_linux.c
	gcc -m32 -o $@ $< -fno-stack-protector

win32-shared: main_linux.c
	i586-mingw32msvc-gcc -m32 -o $@ $< -fno-stack-protector

clean:
	rm -f $(OBJS)
