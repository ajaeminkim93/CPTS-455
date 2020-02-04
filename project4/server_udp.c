#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>

#define SERVER_PORT 5432
#define MAX_LINE 256

int main(int argc, char * argv[])
{
	char *fname;
	char image[MAX_LINE][MAX_LINE];
	char buf[MAX_LINE];
	char recvBuf[MAX_LINE+1]; // recv buffer
	char sendBuf[MAX_LINE+1]; // send buffer
	struct sockaddr_in sin;
	int len;
	int s, i;
	struct timeval tv;
	char seq_num = 1; 
	FILE *fp;
	int lineNum;

	if (argc==2) {
		fname = argv[1];
	}
	else {
		fprintf(stderr, "usage: ./server_udp filename\n");
		exit(1);
	}


	/* build address data structure */
	bzero((char *)&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(SERVER_PORT);

	/* setup passive open */
	if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("simplex-talk: socket");
		exit(1);
	}
	if ((bind(s, (struct sockaddr *)&sin, sizeof(sin))) < 0) {
		perror("simplex-talk: bind");
		exit(1);
	}

	socklen_t sock_len = sizeof sin;

	fp = fopen(fname, "w");
	if (fp==NULL){
		printf("Can't open file\n");
		exit(1);
	}

	while(1){
		// set recvBuf to 0's
		memset(recvBuf, 0, sizeof recvBuf);
		
		// recvfrom receives data on a socket named by a descripter socket and stores it in a buffer.
		// recvfrom(socker, buf, size, flags, sockaddr, addr len)
		// len will be set to the data received from the socket s. The data received will be stored in the buffer recvBuf.
		len = recvfrom(s, recvBuf, sizeof(recvBuf), 0, (struct sockaddr *)&sin, &sock_len);

		// set line number
		lineNum = recvBuf[0];

		if(len == -1){
			perror("PError");
		}    
		else if(len == 1){
			if (recvBuf[0] == 0x02){
				printf("Transmission Complete\n");
				break;
			}
			else{
				perror("Error: Short packet\n");
			}
		}

		else if(len > 1){
			// instead of inputting an error copy the string into the buf on that line.
			strcpy(image[lineNum], recvBuf+1);
		}

		// set sendBuf to 0's
		memset(sendBuf, 0, sizeof sendBuf);
		sendBuf[0] = lineNum;
		if(sendto(s, sendBuf, strlen(sendBuf), 0, (struct sockaddr *)&sin, sock_len)<0){
			perror("SendTo Error\n");
			exit(1);
		}

	} // end of while loop

	// as long as the length of the image(penguin) is not 0, if image doesnt exist then error.
	for(int i = 1; strlen(image[i]) != 0; i++){
		if(fputs((char *) image[i], fp) < 1){
			printf("fputs() error\n");
		}
	}


	fclose(fp);
	close(s);
}
