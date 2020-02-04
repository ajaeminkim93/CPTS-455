#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define SERVER_PORT 5432
#define MAX_LINE 80

int main(int argc, char * argv[])
{
	FILE *fp;
	struct hostent *hp;
	struct sockaddr_in sin;
	char *host;
	char *fname;
	char buf[MAX_LINE];
	char sendbuf[MAX_LINE+4];
	int s;
	int slen;
	char lineNum = 1;
	char recvBuf[MAX_LINE+1];
	int acknowledge;

	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 1000;

	if (argc==3) {
		host = argv[1];
		fname= argv[2];
	}
	else {
		fprintf(stderr, "Usage: ./client_udp host filename\n");
		exit(1);
	}
	/* translate host name into peer’s IP address */
	hp = gethostbyname(host);
	if (!hp) {
		fprintf(stderr, "Unknown host: %s\n", host);
		exit(1);
	}

	fp = fopen(fname, "r");
	if (fp==NULL){
		fprintf(stderr, "Can't open file: %s\n", fname);
		exit(1);
	}

	/* build address data structure */
	bzero((char *)&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	bcopy(hp->h_addr, (char *)&sin.sin_addr, hp->h_length);
	sin.sin_port = htons(SERVER_PORT);

	/* active open */
	if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("Socket");
		exit(1);
	}

	socklen_t sock_len= sizeof sin;

	// setsocketopt(socket descriptor, Level, option name, pointer to option data, length)  
	// set options at the the sockets level. If receive time<0 then error.
	/* set socket open time */
	if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
		perror("PError");
	}

	/* main loop: get and send lines of text */
	while(fgets(buf, 80, fp) != NULL){
		// get length of the str
		slen = strlen(buf);
		// set to null
		buf[slen] ='\0';
		// set sendbuf to 0's
		memset(sendbuf, 0, sizeof sendbuf);
		//set line number to track.
		sendbuf[0] = lineNum;
		// copy buf data to sendbuf
		strcat(sendbuf, buf);
		
		acknowledge = 0;
		while(acknowledge == 0){
			// set recvBuf to 0's
			memset(recvBuf, 0, sizeof recvBuf);
			// sendto sends a message on a socket.
			// sendto(socket, buffer, flags, sock addr, addr length)
			// if message doesnt exist then error.
			if(sendto(s, sendbuf, strlen(sendbuf), 0, (struct sockaddr *)&sin, sock_len)<0){
				perror("SendTo Error\n");
				exit(1);
			}
			// receive message from socket.
			recvfrom(s, recvBuf, sizeof(recvBuf), 0, (struct sockaddr *)&sin, &sock_len);
			// if the message received is the correct line then toggle acknowledged.
			if(recvBuf[0] == lineNum)
				acknowledge = 1;
		}

		lineNum++;
	}
	*buf = 0x02;    
	if(sendto(s, buf, 1, 0, (struct sockaddr *)&sin, sock_len)<0){
		perror("SendTo Error\n");
		exit(1);
	}
	fclose(fp);
}

