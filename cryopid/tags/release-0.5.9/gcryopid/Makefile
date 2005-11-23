CFLAGS = -g -Wall -O2 `pkg-config --cflags gtk+-2.0 libwnck-1.0`
LDFLAGS = `pkg-config --libs gtk+-2.0 libwnck-1.0` -L/usr/X11R6/lib -lXmu

TARGETS = gcryopid

all: $(TARGETS)

gcryopid: gcryopid.o

clean:
	rm -f $(TARGETS) *.o
