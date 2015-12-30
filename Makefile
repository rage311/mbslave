all:
	gcc -o mbslave -L/usr/local/lib -I/usr/local/include mbslave.c -lmodbus
