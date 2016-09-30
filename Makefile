CC = gcc
CFLAGS= -g -Wall -O0
LIBS=-ldwarf -lelf
LIBS+=-lpopt
#LIBS=-l:libdwarf.a -lelf
all:
	$(CC) $(CFLAGS) -o dr dr.c $(LIBS) 
clean:
	rm -f main dr
