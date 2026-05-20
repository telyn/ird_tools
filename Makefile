CC=gcc
CFLAGS=-Wall -std=c99
LDFLAGS= -lz
SOURCES= main.c ird_gz.c ird_build.c ird_iso.c md5.c aes.c ird_rebuild.c
EXECUTABLE=ird_tools
all:
	$(CC) $(CFLAGS) $(SOURCES) $(LDFLAGS) -o $(EXECUTABLE)
install:
	@cp -f ird_tools.exe $(PS3DEV)/bin/ird_tools.exe
clean:
	rm -rf $(EXECUTABLE)
