//1. Show available services to steal a connection
//2. Packet forgery
	//a. Encapsulate original packet
//3. Listen on choosen service for forged packet
//4. Proxy to forward packets in OS

// No npcap, low level always better!

#pragma region pragma comment

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#pragma endregion


#pragma region include

#include <iostream>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <stdio.h>

#include <tchar.h>
#include <string.h>

#include "pcap.h"

#pragma endregion


#pragma region define

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))
#define ADDR_SIZE 128

#pragma endregion


#pragma region proto

int remove_null(char[]);
int show_services();
int forge_packet();
int listen_service();
int decap_packet();
int forward_packet();


#pragma endregion


#pragma region structs


#pragma endregion

// Services
PMIB_TCPTABLE pTcpTable;
DWORD dwSize = 0;
DWORD dwRetVal = 0;

char szLocalAddr[ADDR_SIZE];
char szRemoteAddr[ADDR_SIZE];

struct in_addr IpAddr;

int nServices;
int nService;


// Pcap
pcap_t *fp;
char errbuf[PCAP_ERRBUF_SIZE];
u_char packet[100]; // I will need to allocate it at runtime, because packets will be diffrent sizes i suppose



// netstat -aon | findstr <port>
// tasklist /svc /FI "PID eq <pid from netstat>"

int main()
{
	memset(&szLocalAddr, '\0', ADDR_SIZE);
	memset(&szRemoteAddr, '\0', ADDR_SIZE);


	system("pause");

	//fp = pcap_open_live();


	show_services();

	printf("\n[*] Choose service (%d): ", nServices);
	scanf_s("%d", &nService);

	printf("\n[*] Forging packet\n");
	
	system("pause");

	return 0;
}

#pragma region noforward functions

// remove null bytes from array
int remove_null(char buffer[]) {

	char out[128];

	memset(&out, '\0', ADDR_SIZE);

	int n = 0;
	for (int i = 0; i < ADDR_SIZE; i++) { // 128 size of szLocalAddr and szRemoteAddr
	
		if (buffer[i] != 0) {
			
			out[n] = buffer[i];
			n++;
		}
	}

	for (int i = 0; i < ADDR_SIZE; i++) { // 128 size of szLocalAddr and szRemoteAddr

		buffer[i] = out[i];
	}

	return 0;
}

int show_services() {
	pTcpTable = (MIB_TCPTABLE *)MALLOC(sizeof(MIB_TCPTABLE));
	if (pTcpTable == NULL) {
		printf("Error allocating memory\n");
		return 1;
	}

	dwSize = sizeof(MIB_TCPTABLE);
	// Make an initial call to GetTcpTable to
	// get the necessary size into the dwSize variable
	if ((dwRetVal = GetTcpTable(pTcpTable, &dwSize, TRUE)) ==
		ERROR_INSUFFICIENT_BUFFER) {
		FREE(pTcpTable);
		pTcpTable = (MIB_TCPTABLE *)MALLOC(dwSize);
		if (pTcpTable == NULL) {
			printf("Error allocating memory\n");
			return 1;
		}
	}
	// Make a second call to GetTcpTable to get
	// the actual data we require
	if ((dwRetVal = GetTcpTable(pTcpTable, &dwSize, TRUE)) == NO_ERROR) {
		printf("\tNumber of entries: %d\n", (int)pTcpTable->dwNumEntries);
		for (int i = 0; i < (int)pTcpTable->dwNumEntries; i++) {

			nServices = i;

			if (pTcpTable->table[i].dwState != MIB_TCP_STATE_ESTAB) { continue; }

			printf("\n\tTCP[%d] State: %ld - ", i, pTcpTable->table[i].dwState);
			printf("ESTABLISHED\n");

			IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwLocalAddr;
			InetNtop(AF_INET, &IpAddr.S_un.S_addr, (PWSTR)szLocalAddr, 128);
			remove_null(szLocalAddr);
			printf("\tTCP[%d] Local Addr: %s\n", i, szLocalAddr);

			printf("\tTCP[%d] Local Port: %d \n", i,
				ntohs((u_short)pTcpTable->table[i].dwLocalPort));

			IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwRemoteAddr;
			InetNtop(AF_INET, &IpAddr, (PWSTR)szRemoteAddr, 128);
			remove_null(szRemoteAddr);
			printf("\tTCP[%d] Remote Addr: %s\n", i, szRemoteAddr);

			printf("\tTCP[%d] Remote Port: %d\n", i,
				ntohs((u_short)pTcpTable->table[i].dwRemotePort));
		}
	}
	else {
		printf("\tGetTcpTable failed with %d\n", dwRetVal);
		FREE(pTcpTable);
		return 1;
	}

	if (pTcpTable != NULL) {
		FREE(pTcpTable);
		pTcpTable = NULL;
	}
}

int forge_packet() {

}

int listen_service() {

}

int decap_packet() {

}

int forward_packet() {

}

#pragma endregion

#pragma region pcap functions


#pragma endregion