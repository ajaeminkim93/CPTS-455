#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <net/ethernet.h>

#define BUF_SIZ		65536
#define SEND 0
#define RECV 1
#define S_ARP 2
#define R_ARP 3

void recv_arp(char * iName);

struct arp_header {
    uint16_t hardware_type;
    uint16_t protocol_type;
    unsigned char hardware_len;
    unsigned char protocol_len;
    uint16_t opcode;
    unsigned char sender_mac[6];
    unsigned char sender_ip[4];
    unsigned char target_mac[6];
    unsigned char target_ip[4];
};

struct in_addr get_ip_saddr(char *if_name, int sockfd){
	struct ifreq if_idx;
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, if_name, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFADDR, &if_idx) < 0)
		perror("SIOCGIFADDR");
	return ((struct sockaddr_in *)&if_idx.ifr_addr)->sin_addr;
}

void send_arp(char* address, char* iName ,char* destIp, short type)
{
	printf("Inside ARP Send\n");
	int sockfd, i, byteSent, tx_length = 0;
	struct ifreq if_mac;
	struct ifreq if_idx;
	struct sockaddr_ll sk_addr;
	char sendbuf[BUF_SIZ];
	int sk_addr_size = sizeof(struct sockaddr_ll);
	struct in_addr addr;
	struct ether_header *eh = (struct ether_header *) sendbuf;
	struct arp_header *arp = (struct arp_header *) (sendbuf + sizeof(struct ether_header));

	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		printf("Socket() failed");
	printf("Socket created\n");	

	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, iName, IFNAMSIZ -1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		printf("SIOCGIFINDEX failed");
	printf("Index Set\n");

	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, iName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	    printf("SIOCGIFHWADDR");
	printf("Mac Set\n");
	
	char my_ip[16], my_ip_split[4];
	strcpy(my_ip, inet_ntoa(get_ip_saddr(iName, sockfd)));
	sscanf(my_ip, "%hhd.%hhd.%hhd.%hhd", &my_ip_split[0], &my_ip_split[1], &my_ip_split[2], &my_ip_split[3]);
	
	sk_addr.sll_ifindex = if_idx.ifr_ifindex;
	sk_addr.sll_halen = ETH_ALEN;
	sk_addr.sll_addr[0] = address[0];
	sk_addr.sll_addr[1] = address[1];
	sk_addr.sll_addr[2] = address[2];
	sk_addr.sll_addr[3] = address[3];
	sk_addr.sll_addr[4] = address[4];
	sk_addr.sll_addr[5] = address[5];
	
	memset(sendbuf, 0, BUF_SIZ);
	eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	eh->ether_dhost[0] = address[0];
	eh->ether_dhost[1] = address[1];
	eh->ether_dhost[2] = address[2];
	eh->ether_dhost[3] = address[3];
	eh->ether_dhost[4] = address[4];
	eh->ether_dhost[5] = address[5];
	eh->ether_type = htons(ETH_P_ARP);
	tx_length += sizeof(struct ether_header);

	arp->hardware_type = 1;
	arp->protocol_type = 0x800;
	arp->hardware_len = 6;
	arp->protocol_len = 4;
	arp->opcode = type;
	arp->sender_mac[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	arp->sender_mac[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	arp->sender_mac[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	arp->sender_mac[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	arp->sender_mac[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	arp->sender_mac[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	arp->target_mac[0] = address[0];
	arp->target_mac[1] = address[1];
	arp->target_mac[2] = address[2];
	arp->target_mac[3] = address[3];
	arp->target_mac[4] = address[4];
	arp->target_mac[5] = address[5];
	arp->target_ip[0] = destIp[0];
	arp->target_ip[1] = destIp[1];
	arp->target_ip[2] = destIp[2];
	arp->target_ip[3] = destIp[3];
	arp->sender_ip[0] = my_ip_split[0];
	arp->sender_ip[1] = my_ip_split[1];
	arp->sender_ip[2] = my_ip_split[2];
	arp->sender_ip[3] = my_ip_split[3];
	tx_length += sizeof(struct arp_header);

	byteSent = sendto(sockfd, sendbuf, tx_length, 0,
		(struct sockaddr*)&sk_addr, sk_addr_size);
	printf("byteSent = %d\n", byteSent);
	printf("Listening For Reply!\n");
	if(type == 1)
		recv_arp(iName);
}

void recv_arp(char * iName)
{
	printf("Inside ARP Recv\n");
	int sockfd, recvLen;
	char buf[BUF_SIZ];
	u_int8_t broadcast[6];
	char* broadcast_addr = "ff:ff:ff:ff:ff:ff";
	sscanf(broadcast_addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &broadcast[0], &broadcast[1], &broadcast[2], &broadcast[3], &broadcast[4], &broadcast[5]);
	struct ifreq if_mac;
	struct ifreq if_idx;
	struct sockaddr_ll sk_addr;
	int sk_addr_size = sizeof(struct sockaddr_ll);
	struct ether_header *eh = (struct ether_header *) buf;
	struct arp_header *arp = (struct arp_header *) (buf + sizeof(struct ether_header));

	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		printf("Socket() failed");
	printf("Socket created\n");	

	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, iName, IFNAMSIZ -1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		printf("SIOCGIFINDEX failed");
	printf("Index Set\n");

	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, iName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	    printf("SIOCGIFHWADDR");
	printf("Mac Set\n");
	while(1)
	{
		int invalid = 1;
		while(invalid)
		{
			invalid = 0;
			memset(&sk_addr, 0, sk_addr_size);
			recvLen = recvfrom(sockfd, buf, BUF_SIZ, 0, (struct sockaddr*)&sk_addr, &sk_addr_size);
			printf("recvLen = %d\n", recvLen);
			printf("Broadcast addr = %x:%x:%x:%x:%x:%x\n", broadcast[0], broadcast[1], broadcast[2], 
				broadcast[3], broadcast[4], broadcast[5]);		
			printf("Destination Msg = %x:%x:%x:%x:%x:%x\n", eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2], 
				eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5]);
			printf("Destination Real = %x:%x:%x:%x:%x:%x\n", ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0], 
				((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1], ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2], 
				((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3], ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4], 
				((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5]);
			if((eh->ether_dhost[0] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0] || eh->ether_dhost[1] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1] ||
				eh->ether_dhost[2] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2] || eh->ether_dhost[3] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3] ||
				eh->ether_dhost[4] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4] || eh->ether_dhost[5] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5]) &&
				(eh->ether_dhost[0] != broadcast[0] || eh->ether_dhost[1] != broadcast[1] ||
				eh->ether_dhost[2] != broadcast[2] || eh->ether_dhost[3] != broadcast[3] ||
				eh->ether_dhost[4] != broadcast[4] || eh->ether_dhost[5] != broadcast[5]))
			{
				printf("MAC address invalid, ignoring!\n");
				invalid = 1;
			}
		}
		printf("Source = %x:%x:%x:%x:%x:%x\n", eh->ether_shost[0], eh->ether_shost[1], eh->ether_shost[2], 
			eh->ether_shost[3], eh->ether_shost[4], eh->ether_shost[5]);
		printf("Type = %hi\n", eh->ether_type);
		char my_ip[16], my_ip_split[4];
		strcpy(my_ip, inet_ntoa(get_ip_saddr(iName, sockfd)));
		sscanf(my_ip, "%hhd.%hhd.%hhd.%hhd", &my_ip_split[0], &my_ip_split[1], &my_ip_split[2], &my_ip_split[3]);
		if(arp->opcode == 1)
		{
			printf("ARP Request Received!\n");
			printf("My IP = %s\n", my_ip);
			printf("Target IP = %d.%d.%d.%d\n", arp->target_ip[0], arp->target_ip[1], arp->target_ip[2], arp->target_ip[3]);
			if(arp->target_ip[0] == my_ip_split[0] && arp->target_ip[1] == my_ip_split[1] && arp->target_ip[2] == my_ip_split[2] && arp->target_ip[3] == my_ip_split[3])
			{
				printf("Sender MAC Address = %x:%x:%x:%x:%x:%x\n", arp->sender_mac[0], arp->sender_mac[1], arp->sender_mac[2], 
					arp->sender_mac[3], arp->sender_mac[4], arp->sender_mac[5]);
				printf("Sender IP = %d.%d.%d.%d\n", arp->sender_ip[0], arp->sender_ip[1], arp->sender_ip[2], arp->sender_ip[3]);
				send_arp(eh->ether_dhost, iName, arp->sender_ip, 2);
				printf("ARP Reply Sent!\n");
				return;
			}
			else
			{
				printf("Not my IP!\n");
			}
		}
		if(arp->opcode == 2)
		{
			printf("ARP Reply Received!\n");
			printf("My IP = %s\n", my_ip);
			printf("Target IP = %d.%d.%d.%d\n", arp->target_ip[0], arp->target_ip[1], arp->target_ip[2], arp->target_ip[3]);
			if(arp->target_ip[0] == my_ip_split[0] && arp->target_ip[1] == my_ip_split[1] && arp->target_ip[2] == my_ip_split[2] && arp->target_ip[3] == my_ip_split[3])
			{
				printf("Sender MAC Address = %x:%x:%x:%x:%x:%x\n", arp->sender_mac[0], arp->sender_mac[1], arp->sender_mac[2], 
					arp->sender_mac[3], arp->sender_mac[4], arp->sender_mac[5]);
				printf("Sender IP = %d.%d.%d.%d\n", arp->sender_ip[0], arp->sender_ip[1], arp->sender_ip[2], arp->sender_ip[3]);
				return;
			}
			else
			{
				printf("Not my IP!\n");
			}
		}
	}
}

void send_message(char* address, char* iName ,char* message)
{
	printf("Inside Send\n");
	int sockfd, i, byteSent, tx_length = 0;
	struct ifreq if_mac;
	struct ifreq if_idx;
	struct sockaddr_ll sk_addr;
	char sendbuf[BUF_SIZ];
	struct ether_header *eh = (struct ether_header *) sendbuf;
	int sk_addr_size = sizeof(struct sockaddr_ll);

	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		printf("Socket() failed");
	printf("Socket created\n");	

	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, iName, IFNAMSIZ -1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		printf("SIOCGIFINDEX failed");
	printf("Index Set\n");

	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, iName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	    printf("SIOCGIFHWADDR");
	printf("Mac Set\n");

	memset(sendbuf, 0, BUF_SIZ);
	eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	eh->ether_dhost[0] = address[0];
	eh->ether_dhost[1] = address[1];
	eh->ether_dhost[2] = address[2];
	eh->ether_dhost[3] = address[3];
	eh->ether_dhost[4] = address[4];
	eh->ether_dhost[5] = address[5];
	eh->ether_type = htons(ETH_P_IP);
	tx_length += sizeof(struct ether_header);

	for(i = 0; i < strlen(message); i++)
	{
		sendbuf[tx_length+i] = message[i];
	}
	tx_length += i;
	
	sk_addr.sll_ifindex = if_idx.ifr_ifindex;
	sk_addr.sll_halen = ETH_ALEN;
	sk_addr.sll_addr[0] = address[0];
	sk_addr.sll_addr[1] = address[1];
	sk_addr.sll_addr[2] = address[2];
	sk_addr.sll_addr[3] = address[3];
	sk_addr.sll_addr[4] = address[4];
	sk_addr.sll_addr[5] = address[5];

	byteSent = sendto(sockfd, sendbuf, tx_length, 0,
		(struct sockaddr*)&sk_addr, sk_addr_size);
	printf("byteSent = %d\n", byteSent);
	printf("message = %s\n", message);

}

void recv_message(char * iName)
{
	printf("Inside Recv\n");
	int sockfd, recvLen;
	char buf[BUF_SIZ];
	struct ifreq if_mac;
	struct ifreq if_idx;
	struct sockaddr_ll sk_addr;
	int sk_addr_size = sizeof(struct sockaddr_ll);
	struct ether_header *eh = (struct ether_header *) buf;

	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		printf("Socket() failed");
	printf("Socket created\n");	

	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, iName, IFNAMSIZ -1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		printf("SIOCGIFINDEX failed");
	printf("Index Set\n");

	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, iName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	    printf("SIOCGIFHWADDR");
	printf("Mac Set\n");

	memset(&sk_addr, 0, sk_addr_size);
	recvLen = recvfrom(sockfd, buf, BUF_SIZ, 0, (struct sockaddr*)&sk_addr, &sk_addr_size);
	printf("recvLen = %d\n", recvLen);
	printf("Destination Msg = %x:%x:%x:%x:%x:%x\n", eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2], 
		eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5]);
	printf("Destination Real = %x:%x:%x:%x:%x:%x\n", ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0], 
		((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1], ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2], 
		((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3], ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4], 
		((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5]);
	if(eh->ether_dhost[0] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0] || eh->ether_dhost[1] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1] ||
		eh->ether_dhost[2] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2] || eh->ether_dhost[3] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3] ||
		eh->ether_dhost[4] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4] || eh->ether_dhost[5] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5])
	{
		printf("MAC adresses do not match, ignoring!\n");
		return;
	}
	printf("Source = %x:%x:%x:%x:%x:%x\n", eh->ether_shost[0], eh->ether_shost[1], eh->ether_shost[2], 
		eh->ether_shost[3], eh->ether_shost[4], eh->ether_shost[5]);
	printf("Type = %hi\n", eh->ether_type);
	printf("Payload = ");
	for(int i = sizeof(struct ether_header); i < recvLen; i++)
	{
		printf("%c", buf[i]);
	}
	printf("\n");

}

int main(int argc, char *argv[])
{
	int mode;
	char hw_addr[6];
	char dest_ip[4];
	char interfaceName[IFNAMSIZ];
	char buf[BUF_SIZ];
	memset(buf, 0, BUF_SIZ);
	
	int correct=0;
	if (argc > 1){
		if(strncmp(argv[1],"Send", 4)==0)
		{
			if (argc == 5)
			{
				mode=SEND; 
				sscanf(argv[3], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &hw_addr[0], &hw_addr[1], &hw_addr[2], &hw_addr[3], &hw_addr[4], &hw_addr[5]);
				strncpy(buf, argv[4], BUF_SIZ);
				correct=1;
				printf("  buf: %s\n", buf);
			}
		}
		else if(strncmp(argv[1],"Recv", 4)==0)
		{
			if (argc == 3)
			{
				mode=RECV;
				correct=1;
			}
		}
		else if(strncmp(argv[1],"S_ARP", 5)==0)
		{
			if (argc == 4)
			{
				mode = S_ARP;
				char* broadcast_addr = "ff:ff:ff:ff:ff:ff";
				sscanf(broadcast_addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &hw_addr[0], &hw_addr[1], &hw_addr[2], &hw_addr[3], &hw_addr[4], &hw_addr[5]);
				sscanf(argv[3], "%hhd.%hhd.%hhd.%hhd", &dest_ip[0], &dest_ip[1], &dest_ip[2], &dest_ip[3]);
				correct=1;
			}
		}
		else if(strncmp(argv[1],"R_ARP", 5)==0)
		{
			if (argc == 3)
			{
				mode = R_ARP;
				correct=1;
			}
		}
		strncpy(interfaceName, argv[2], IFNAMSIZ);
	 }
	if(!correct)
	{
		fprintf(stderr, "./455_proj2 Send <InterfaceName>  <DestHWAddr> <Message>\n");
		fprintf(stderr, "./455_proj2 Recv <InterfaceName>\n");
		fprintf(stderr, "./455_proj2 S_ARP <InterfaceName> <DestIP>\n");
		fprintf(stderr, "./455_proj2 R_ARP <InterfaceName>\n");
		exit(1);
	}

	if(mode == SEND)
	{
		send_message(hw_addr, interfaceName, buf);
	}
	else if (mode == RECV)
	{
		recv_message(interfaceName);
	}
	else if (mode == S_ARP)
	{
		send_arp(hw_addr, interfaceName, dest_ip, 1);
	}
	else if (mode == R_ARP)
	{
		recv_arp(interfaceName);
	}
	return 0;
}

