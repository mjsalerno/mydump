CC = gcc
CFLAGS = -g -Wall -Werror 
LIBS = -lpcap
BIN = mydump

.PHONY: clean all tags

all: mydump

mydump: mydump.o
	$(CC) $(CFLAGS) -o $(BIN) mydump.o $(LIBS)

mydump.o: mydump.c mydump.h
	$(CC) $(CFLAGS) -c mydump.c

clean:
	rm -f *.o *.out mydump


tags:
	find . -name "*.[chw]" > cscope.files
	ctags -R *
	cscope -b -q -k
	~/git/YCM-Generator/config_gen.py .

