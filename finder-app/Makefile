CC=$(CROSS_COMPILE)gcc

all: writer.o
	$(CC) writer.o -o writer
writer.o: writer.c
	$(CC) -c writer.c -o writer.o -Wall

clean:
	rm -f writer writer.o
