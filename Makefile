hottool: crossprocess.o find_sym_addr.o hook.o main.o
	g++ main.o crossprocess.o find_sym_addr.o hook.o -g -Wl,-export-dynamic -o hottool

crossprocess.o: crossprocess.cpp crossprocess.h
	g++ -c crossprocess.cpp -g -Wl,-export-dynamic

hook.o: hook.cpp hook.h
	g++ -c hook.cpp -g -Wl,-export-dynamic

find_sym_addr.o: find_sym_addr.cpp find_sym_addr.h
	g++ -c find_sym_addr.cpp  -g -Wl,-export-dynamic

main.o: main.cpp
	g++ -c main.cpp  -g -Wl,-export-dynamic

clean:
	rm -f *.o hottool
