
hotfix: crossprocess.o find_sym_addr.o hook.o hotfix.o
    g++ hotfix.o crossprocess.o find_sym_addr.o hook.o -g -Wl,-export-dynamic -o hottool

hotfind: crossprocess.o find_sym_addr.o hook.o hotfind.o
    g++ hotfind.o crossprocess.o find_sym_addr.o hook.o -g -Wl,-export-dynamic -o hottool

crossprocess.o: crossprocess.cpp crossprocess.h
    g++ -c crossprocess.cpp -g -Wl,-export-dynamic

hook.o: hook.cpp hook.h
    g++ -c hook.cpp -g -Wl,-export-dynamic

find_sym_addr.o: find_sym_addr.cpp find_sym_addr.h
    g++ -c find_sym_addr.cpp  -g -Wl,-export-dynamic

hotfind.o: hotfind.cpp
    g++ -c hotfind.cpp  -g -Wl,-export-dynamic

clean:
    rm -f *.o hotfix hotfind
