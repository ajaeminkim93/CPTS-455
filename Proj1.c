#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
// #include <net/if.h>
#include <netinet/ether.h>
#include <linux/if.h>
#define BUF_SIZ		65536
#define SEND 0
#define RECV 1


		// interface name, hardware address, message
void send_msg(char *ifName, int hardwareAddr[], char msg[]) {
	
	int socketSend;
	int txtLen = 0, i;
	char *interfaceHolder, dataBuffer[BUF_SIZ];

	struct ifreq if_idx;
        struct ifreq if_mac;
	struct ethhdr *ethernetHeader;
	struct sockaddr_ll socketAddr;

	// Open the Socket as a Raw Socket
	socketSend = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	// Error opening the socket.
	if(socketSend < 0) printf("Socket Failure\n");
	printf("Created the socket");

	interfaceHolder = (char *) malloc(sizeof(ifName));
	memset(interfaceHolder, 0, sizeof(ifName));
	strcpy(interfaceHolder, ifName);

	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, interfaceHolder, IFNAMSIZ-1);
	//Get interface index
	if((ioctl(socketSend, SIOCGIFINDEX, &if_idx)< 0)) printf("ERROR: SIOCGIFINDEX failure\n");
	printf("The Index Set: \n");

	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, interfaceHolder, IFNAMSIZ-1);
	//Get MAC address of interface
	if((ioctl(socketSend, SIOCGIFHWADDR, &if_mac))< 0) printf("ERROR: SIOCGIFHWADDR failure\n");
	printf("The Mac Set: \n");

	memset(dataBuffer,0, BUF_SIZ);
	ethernetHeader = (struct ethhdr *)(dataBuffer);

	
	// Create ethernerHeader hardware source.
	i = 0;
	while (i < ETH_ALEN) {
		ethernetHeader->h_source[i] = (unsigned char)(if_mac.ifr_hwaddr.sa_data[i]);
		i++;
	}
	printf("MAC Address\n");

	// Store in destination hardware. 
	i = 0;
	while (i < ETH_ALEN) {
		ethernetHeader->h_dest[i] = hardwareAddr[i];
		i++;
	}
	printf("Done storing in hardware destination.\n");

	// Set etherType
	ethernetHeader->h_proto = htons(ETH_P_IP);	
	txtLen += sizeof(struct ethhdr);
	
	// store message
	for (i = 0; msg[i] != '\0'; i++){
		dataBuffer[txtLen++] = msg[i];
	}
	
	// The Network Index.
	socketAddr.sll_ifindex = if_idx.ifr_ifindex;
	// Length of the Address.
	socketAddr.sll_halen = ETH_ALEN; 
	
	// Store in the destination MAC.	
	i = 0;
	while (i < ETH_ALEN) {
		socketAddr.sll_addr[i] = hardwareAddr[i];
		i++;
	}
	
	if(sendto(socketSend, dataBuffer, txtLen, 0, (struct sockaddr*)&socketAddr, sizeof(struct sockaddr_ll)) < 0) {
		printf("Message Send Failed...\n");
	} 

	printf("Message has been  sent!\n");
	free(interfaceHolder);
}

void recv_msg(char* interface) {
	int socketRecv;
	int ehSize;
	int sockAddress_len = sizeof(struct sockaddr), buffCheck = 0;
	unsigned char *buffer = (unsigned char *) malloc(BUF_SIZ);
	struct sockaddr sockAddress; 

	// Open a raw socket to receive packets.
	socketRecv = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if( socketRecv < 0) printf("Socket Faield\n");
	printf("Socket Created\n");
		

	printf("Waiting to Receive a message\n");
	// Checking buf, waiting for a message.
	while(buffCheck == 0) {
		buffCheck = recvfrom(socketRecv, buffer, BUF_SIZ, 0, &sockAddress, (socklen_t *) &sockAddress_len);
	}
	printf("Message Received\n");

	// Store ethernet header.
	struct ethhdr *ether = (struct ethhdr *) (buffer);
	ehSize = sizeof(struct ethhdr);

	// Reading the message directly from teh buffer.
	unsigned char *msg = (buffer + ehSize );
	printf("The Current Received Message: %s\n", msg);
	free(buffer);
}

int main(int argc, char *argv[]) {
	int mode;
	int hw_addr[6];
	int sk_addr_size = sizeof(struct sockaddr_ll);
	char ifName[IFNAMSIZ];
	char buf[BUF_SIZ];
	struct sockaddr_ll sk_addr;
	memset(buf, 0, BUF_SIZ);

	int correct=0;
	if (argc > 1) {
		if(strncmp(argv[1],"Send", 4)==0){
			if (argc == 5){
				mode=SEND; 
				printf("Interface: %s\n", argv[2]);
				sscanf(argv[3], "%02x:%02x:%02x:%02x:%02x:%02x", &hw_addr[0], &hw_addr[1], &hw_addr[2], &hw_addr[3], &hw_addr[4], &hw_addr[5]);
				printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", hw_addr[0], hw_addr[1],hw_addr[2],hw_addr[3],hw_addr[4], hw_addr[5]);
				strncpy(buf, argv[4], BUF_SIZ);
				correct=1;
				printf("  buf: %s\n", buf);
			}
		}
		else if(strncmp(argv[1],"Recv", 4)==0){
			if (argc == 3){
				mode=RECV;
				correct=1;
			}
		}
		strncpy(ifName, argv[2], IFNAMSIZ);
	 }
	 if(!correct){
		fprintf(stderr, "./455_proj2 Send <InterfaceName>  <DestHWAddr> <Message>\n");
		fprintf(stderr, "./455_proj2 Recv <InterfaceName>\n");
		exit(1);
	 }

	//Do something here

	if(mode == SEND){
		send_msg(ifName, hw_addr, buf);
	}
	else if (mode == RECV){
		
		recv_msg(ifName);
	}

	return 0;
}

