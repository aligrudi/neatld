CC = cc
CFLAGS = -Wall -Os
LDFLAGS =

all: ld
.c.o:
	$(CC) -c $(CFLAGS) $<
ld: ld.o
	$(CC) $(LDFLAGS) -o $@ $^
clean:
	rm -f ld *.o
