PROG = conenatd
DEP = $(shell find ./ -name "*.h")
SRC = $(shell find ./ -name "*.c")
OBJ = $(SRC:%.c=%.o)
LIB = -lpthread -lnetfilter_queue -lmnl -lnetfilter_conntrack

CC ?= gcc
STRIP ?= strip

$(PROG): $(OBJ)
	$(CC) $(LDFLAGS) -o $(PROG) $(OBJ) $(LIB)
	$(STRIP) $(PROG)

%.o: %.c $(DEP)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ) $(PROG)
