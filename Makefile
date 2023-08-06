CC = gcc
CFLAGS = -O2 `pkg-config --cflags gtk4` -Iinclude
LFLAGS = -O2 `pkg-config --libs gtk4` -Iinclude
BIN = pyxploit.o dereference.o memory.o
EXE = pyxploit

$(EXE): $(BIN) 
	$(CC) $(BIN) $(LFLAGS) -o $(EXE)

pyxploit.o: pyxploit.c
	$(CC) -c pyxploit.c $(CFLAGS)

dereference.o: dereference.c
	$(CC) -c dereference.c $(CFLAGS)

memory.o: memory.c
	$(CC) -c memory.c $(CFLAGS)


clean:
	rm *.o
