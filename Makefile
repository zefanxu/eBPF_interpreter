HEADERS = ebpf.h
FLAGS = -c -g -O2

default: interpreter

interpreter_execution.o: interpreter_execution.c $(HEADERS)
	gcc $(FLAGS)  interpreter_execution.c -o interpreter_execution.o

interpreter.o: interpreter.c $(HEADERS)
	gcc $(FLAGS) interpreter.c -o interpreter.o

file.o: file.c $(HEADERS)
	gcc $(FLAGS) file.c -o file.o

interpreter: interpreter.o file.o interpreter_execution.o
	gcc -g interpreter.o file.o interpreter_execution.o -o interpreter

clean:
	-rm -f *.o
	-rm -f interpreter
