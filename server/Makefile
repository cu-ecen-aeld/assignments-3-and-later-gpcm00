CC ?= $(CROSS_COMPILE)gcc
CFLAGS ?= -g -Wall -Werror
LDFLAGS ?= -pthread
OBJ := server.o list.o

all: $(OBJ)
	$(CC) $(OBJ) -o aesdsocket $(LDFLAGS)
	
%.o : %.c
	$(CC) -c $< -o $@ $(CFLAGS) 

clean:
	$(RM) -f aesdsocket $(OBJ)
