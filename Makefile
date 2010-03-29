CC = dietcc
CFLAGS = -Wall -O2 -g
LDFLAGS = -g

all: ld a.out
.c.o:
	$(CC) -c $(CFLAGS) $<
ld: ld.o
	$(CC) $(LDFLAGS) -o $@ $^
a.out: ld
	./ld t/test.o
clean:
	rm -f ld *.o a.out core
