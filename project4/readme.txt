How to Compile:
1. Run 	gcc -o server.bin server_udp.c
	gcc -o client.bin client_udp.c 

How to Run:
1. sudo mn -c

2. sudo mn --mac --switch ovsk --controller remote,port=6633  // this was the port number for mine

// if you havent already...
3. git clone http://github.com/noxrepo/pox
4. mv proj4_455.py ~/pox/pox/misc/

5. In a separate terminal
	cd pox
	./pox.py log.level --DEBUG misc.proj4_455

6. Confirm that pox is listening on the port.

7. Inside of mininet:
	h2 ./server.bin output.txt &
	h1 ./client.bin 10.0.0.2 tux.txt

5. diff tux.txt output.txt, to check.
