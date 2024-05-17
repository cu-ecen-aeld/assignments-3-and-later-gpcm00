CC ?= $(CROSS_COMPILE)gcc
CFLAGS ?= -g -Wall -Werror
LDFLAGS ?= -lpthread
OBJ ?= server.o list.o

all: $(OBJ)
	$(CC) $(OBJ) -o aesdsocket $(LDFLAGS)
	
%.o : %.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -f aesdsocket $(OBJ)
