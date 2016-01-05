CROSS = armv6z-xxx442_001-linux-gnueabi-
CC = g++
TARGET = tellzip
OBJS = tellzip.o

#EXTLIB = -lpthread


GCLIBCDIR = /usr/local/xxx-toolchain/gnuarm-4.4.2/cross-tools/arm11
CFLAGS += -I$(GCLIBCDIR)/include -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE
LDFLAGS += -L$(GCLIBCDIR)/lib

all: $(TARGET)


tellzip: $(OBJS)
	$(CROSS)$(CC) $(LDFLAGS) $(EXTLIB) -o $@ $^

.c.o:
	$(CROSS)$(CC) $(CFLAGS) $(EXTLIB) -c $< -o $@

clean:
	rm -f *.o $(TARGET)
