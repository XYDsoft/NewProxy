#include <stdio.h>
#include "Driver.h"
#include "nfapi.h"

#include <ws2tcpip.h>


int inet_pton(int af, const char *csrc, void *dst)
{
    char * src;

    if (csrc == NULL || (src = strdup(csrc)) == NULL) {
	return 0;
    }

    switch (af) {
    case AF_INET:
	{
	    struct sockaddr_in  si4;
	    INT r;
	    INT s = sizeof(si4);

	    si4.sin_family = AF_INET;
	    r = WSAStringToAddress(src, AF_INET, NULL, (LPSOCKADDR) &si4, &s);
	    free(src);
	    src = NULL;

	    if (r == 0) {
		memcpy(dst, &si4.sin_addr, sizeof(si4.sin_addr));
		return 1;
	    }
	}
	break;

    case AF_INET6:
	{
	    struct sockaddr_in6 si6;
	    INT r;
	    INT s = sizeof(si6);

	    si6.sin6_family = AF_INET6;
	    r = WSAStringToAddress(src, AF_INET6, NULL, (LPSOCKADDR) &si6, &s);
	    free(src);
	    src = NULL;

	    if (r == 0) {
		memcpy(dst, &si6.sin6_addr, sizeof(si6.sin6_addr));
		return 1;
	    }
	}
	break;

    default:
	return -1;
    }

    {
	int le = WSAGetLastError();

	if (le == WSAEINVAL)
	    return 0;
	
	return -1;
    }
}




//netfilter2

#define NFDRIVER_NAME "netfilter2"

//C调Golang函数
extern void go_threadStart();
extern void go_threadEnd();
extern void go_tcpConnectRequest(ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo);
extern void go_tcpConnected(ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo);
extern void go_tcpClosed(ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo);
extern void go_tcpReceive(ENDPOINT_ID id, const char * buf, int len);
extern void go_tcpSend(ENDPOINT_ID id, const char * buf, int len);
extern void go_tcpCanReceive(ENDPOINT_ID id);
extern void go_tcpCanSend(ENDPOINT_ID id);
extern void go_udpCreated(ENDPOINT_ID id, PNF_UDP_CONN_INFO pConnInfo);
extern void go_udpConnectRequest(ENDPOINT_ID id, PNF_UDP_CONN_REQUEST pConnReq);
extern void go_udpClosed(ENDPOINT_ID id, PNF_UDP_CONN_INFO pConnInfo);
extern void go_udpReceive(ENDPOINT_ID id, const unsigned char * remoteAddress, const char * buf, int len, PNF_UDP_OPTIONS options);
extern void go_udpSend(ENDPOINT_ID id, const unsigned char * remoteAddress, const char * buf, int len, PNF_UDP_OPTIONS options);
extern void go_udpCanReceive(ENDPOINT_ID id);
extern void go_udpCanSend(ENDPOINT_ID id);




void threadStart(){
	go_threadStart();
}
void threadEnd(){
	go_threadEnd();
}
void tcpConnectRequest(ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo){
	go_tcpConnectRequest(id,pConnInfo);
}
void tcpConnected(ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo){
	go_tcpConnected(id,pConnInfo);
}
void tcpClosed(ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo){
	go_tcpClosed(id,pConnInfo);
}
void tcpReceive(ENDPOINT_ID id, const char * buf, int len){
	go_tcpReceive(id,buf,len);
}
void tcpSend(ENDPOINT_ID id, const char * buf, int len){
	go_tcpSend(id,buf,len);
}
void tcpCanReceive(ENDPOINT_ID id){
	go_tcpCanReceive(id);
}
void tcpCanSend(ENDPOINT_ID id){
	go_tcpCanSend(id);
}
void udpCreated(ENDPOINT_ID id, PNF_UDP_CONN_INFO pConnInfo){
	go_udpCreated(id,pConnInfo);
}
void udpConnectRequest(ENDPOINT_ID id, PNF_UDP_CONN_REQUEST pConnReq){
	go_udpConnectRequest(id,pConnReq);
}
void udpClosed(ENDPOINT_ID id, PNF_UDP_CONN_INFO pConnInfo){
	go_udpClosed(id,pConnInfo);
}
void udpReceive(ENDPOINT_ID id, const unsigned char * remoteAddress, const char * buf, int len, PNF_UDP_OPTIONS options){
	go_udpReceive(id,remoteAddress,buf,len,options);
}
void udpSend(ENDPOINT_ID id, const unsigned char * remoteAddress, const char * buf, int len, PNF_UDP_OPTIONS options){
    go_udpSend(id,remoteAddress,buf,len,options);
}
void udpCanReceive(ENDPOINT_ID id){
	go_udpCanReceive(id);
}
void udpCanSend(ENDPOINT_ID id){
	go_udpCanSend(id);
}


//////////////////////////////////控制程序////////////////////////////////

NF_EventHandler eh = { 
		threadStart,
		threadEnd,
		tcpConnectRequest,
		tcpConnected,
		tcpClosed,
		tcpReceive,
		tcpSend,
		tcpCanReceive,
		tcpCanSend,
		udpCreated,
		udpConnectRequest,
		udpClosed,
		udpReceive,
		udpSend,
		udpCanReceive,
		udpCanSend
	};
    
void DriverFree () {  
    nf_deleteRules ();
    nf_free();
}

int DriverMain(){
	return nf_init(NFDRIVER_NAME, &eh);
}


int cPort = 0;
char * c4addr = "";
char * c6addr = "";


void setPort(int a,char * b,char * c){
    
    cPort = a;
    c4addr = b;
    c6addr = c;
}


void setAddrV4(void *ppDetectInfo)
{
    struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(c4addr);
	addr.sin_port =  htons(cPort);
    
    memcpy(ppDetectInfo, &addr, sizeof(addr));
}

void setAddrV6(void *ppDetectInfo)
{
    struct sockaddr_in6 addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, c6addr,&addr.sin6_addr);
	addr.sin6_port =  htons(cPort);
    
    memcpy(ppDetectInfo, &addr, sizeof(addr));
}