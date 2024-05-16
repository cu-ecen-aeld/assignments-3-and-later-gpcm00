CC=$(CROSS_COMPILE)gcc
CFLAGS=-Wall -Werror
OBJ_FILES=server.o list.o


all: $(OBJ_FILES)
	$(CC) $(OBJ_FILES) -o aesdsocket -pthread
server.o: server.c
	$(CC) -c server.c -o server.o $(CFLAGS)

list.o: list.c
	$(CC) -c list.c -o list.o $(CFLAGS)

clean:
	rm -f aesdsocket server.o list.o