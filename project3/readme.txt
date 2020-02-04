How to compile
1. Run the following command
	gcc proj3.c -o proj3.bin

How to run the code using Mininet and Xterm:
Start mininet
	ie. sudo ./router.py
Get the ip address of h3x2
	ie. h3x2 ifconfig
Get the ip address of the router
	ie. r0 ifconfig
Start a xterminal for the receiver
	ie. xterm h3x2
Run the receiver
	ie. ./proj3.bin Recv h3x2-eth0
Start a terminal for the Sender
	ie. xterm h1x1
Run the sender
	ie. ./proj3.bin Send h1-eth0 <h3x2 IP addr> <router IP addr> '<message>'
		    for example..    //10.0.0.101   //192.168.1.1   // 'test'
