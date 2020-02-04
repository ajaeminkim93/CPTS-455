How to Compile:
Run the following command
	gcc main.c -o proj2arp.bin

How to Run the code using MiniNet and Xterm:
Start mininet
	ie. mn
Get the ip address of host 2 node
	ie. h2 ifconfig -a
Start a xterminal for the receiver
	ie. xterm h2
Run the receiver
	ie. ./arp.bin R_ARP h2-eth0
Start a xterminal for the sender
	ie. xterm h2
Run the sender
	ie. ./arp.bin S_ARP h1-eth0 <h2 IP addr> 

