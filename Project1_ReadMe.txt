Instructions to run program: (compiled using gcc)

Step 1: Set up the mininet by sudo mn
	
Step 2: Run "<interface> xterm &" on the mininet nodes you are going to use by h1 xterm &

Step 3: Run "ifconfig -a" in the node that will be receiving the node's MAC address.

Step 4: In the node that will be receiving run: ./455_Proj1_executable Recv <interfaceName>
	i.e. "./455_Proj1_executable Recv h2-eth0"

Step 5: In the node that will be sending the message, run: ./Proj1exec Send <interfaceName> <ReceivingMacAddress> <messageToSend>
	i.e. "./Proj1exec Send 01:23:45:67:89:ab helloWorld"
	     "./Proj1exec Send 01:23:45:67:89:ab 'This is a Message' "

