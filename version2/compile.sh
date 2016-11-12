gcc -m32 -c sym_table.c -o sym_table.o
gcc -m32 -c main.c -o main.o
gcc -m32 main.o sym_table.o -o stackVis

