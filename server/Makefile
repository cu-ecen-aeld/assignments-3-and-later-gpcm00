CC=$(CROSS_COMPILE)gcc

all: server.o
	$(CC) server.o -o aesdsocket -pthread
writer.o: server.c
	$(CC) -c server.c -o server.o -Wall

clean:
	rm -f aesdsocket server.o