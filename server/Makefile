CC ?= $(CROSS_COMPILE)gcc
CFLAGS ?= -g -Wall -Werror
LDFLAGS ?= -pthread
OBJ := server.o list.o
INC := -I../aesd-char-driver

all: $(OBJ)
	$(CC) $(OBJ) -o aesdsocket $(LDFLAGS)
	
%.o : %.c
	$(CC) -c $< -o $@ $(CFLAGS) $(INC)

clean:
	$(RM) -f aesdsocket $(OBJ)
