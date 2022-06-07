#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>

#define BUF_LEN 256

int main(int argc, char **argv) {
	int err = 0;
	int fd = 0;
	//Set URL
	/*
	 * TODO: Add SSL support for https requests
	char *host = "api.fiscaldata.treasury.gov\0";
	char *endpt = "/services/api/fiscal_service/v1/accounting/od/schedules_fed_debt_daily_activity?filter=record_date:eq:2022-05-01\0"; 
	*/
	char *host = "www.google.com\0";
	char *endpt = "/index.html\0";
	//Configure everything for connection to server
	struct addrinfo hints, *res; 
	//Init everything to zero
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = PF_UNSPEC; 
	hints.ai_socktype = SOCK_STREAM;
	//Get list of IP addresses and port numbers for host name
	err = getaddrinfo(host, "http", &hints, &res);
	if(err != 0) {
		const char *msg = gai_strerror(err); 
		fprintf(stderr, "getaddrinfo: %s\n", msg);
		return -1; 
	}
	while(res != NULL) {
		//fyi HTTP uses stream sockets which relies on TCP
		fd = socket(res->ai_family, 
			    res->ai_socktype, 
			    res->ai_protocol);
		if(fd == -1) {
			perror("socket: \n");
			res = res->ai_next;
			continue;
		}
		err = connect(fd, res->ai_addr, res->ai_addrlen); 
		if(err == -1) {
			perror("connect: \n");
			close(fd);
			res = res->ai_next;
			continue;
		}
		//We have a successful web socket
		break;
	}
	if(fd < 0) {
		fprintf(stderr, "Failed to make socket\n");
		freeaddrinfo(res);
		return -1; 
	}
	//Send the GET request to the server
	int bytes = 0; 
	int bytes_sent = 0;
	char buffer[BUF_LEN];
	//CLRF: Moves cursor to beginning of next line
	err = snprintf(buffer, BUF_LEN, 
		 "GET %s HTTP/1.1 \r\nHost: %s \r\nConnection: close\r\n\r\n",
		 endpt, host);
	if(err < 0) {
		fprintf(stderr, "snprintf\n");
		close(fd);
		freeaddrinfo(res);
		return -1; 
	}
	while(bytes_sent < strlen(buffer)) {
		bytes = send(fd, &buffer, strlen(buffer), 0);
		if(bytes == -1) {
			perror("send ");
			close(fd);
			freeaddrinfo(res);
			return -1;
		}
		bytes_sent += bytes;
	}
	memset(buffer, 0, BUF_LEN);
	//Recieve the data from the server
	bytes = 1;
	while(bytes != 0) {
		bytes = recv(fd, &buffer, BUF_LEN, 0);
		if(bytes == -1) {
			perror("recv ");
			close(fd);
			freeaddrinfo(res);
			return -1;
		}
		printf("%s", buffer);
		memset(buffer, 0, BUF_LEN);
	}
	close(fd);
	freeaddrinfo(res);
	return 0;
}
