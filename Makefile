CC = gcc
CFLAGS = -O2 `pkg-config --cflags gtk4` -Iinclude
LFLAGS = -O2 `pkg-config --libs gtk4` -Iinclude
BIN = pydissector.o dereference.o memory.o
EXE = pydissector

$(EXE): $(BIN) 
	$(CC) $(BIN) $(LFLAGS) -o $(EXE)

pydissector.o: pydissector.c
	$(CC) -c pydissector.c $(CFLAGS)

dereference.o: dereference.c
	$(CC) -c dereference.c $(CFLAGS)

memory.o: memory.c
	$(CC) -c memory.c $(CFLAGS)


clean:
	rm *.o
