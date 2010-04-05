CC = cc
CFLAGS = -Wall -O2 -g
LDFLAGS = -g

all: ld
.c.o:
	$(CC) -c $(CFLAGS) $<
ld: ld.o
	$(CC) $(LDFLAGS) -o $@ $^
clean:
	rm -f ld *.o
