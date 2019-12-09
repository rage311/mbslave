all:
	cc -o mbslave -L/usr/local/lib -I/usr/local/include mbslave.c -lmodbus

	#cc -o mbslave -L/usr/local/lib -I/usr/include/modbus mbslave.c -lmodbus
