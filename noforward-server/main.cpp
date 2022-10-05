#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <tchar.h>
#include <string.h>

#include "pcap.h"

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))
#define ADDR_SIZE 128

int remove_null(char[]);
int show_services();

BOOL LoadNpcapDlls();
void ifprint(pcap_if_t*);
char *iptos(u_long);



// Services
PMIB_TCPTABLE pTcpTable;
DWORD dwSize = 0;
DWORD dwRetVal = 0;

char szLocalAddr[ADDR_SIZE];
char szRemoteAddr[ADDR_SIZE];

struct in_addr IpAddr;

u_int nServices;
u_int nService;


// Pcap
pcap_if_t *alldevs;
pcap_if_t *d;
u_int nDevs = 0;
u_int nDev;

pcap_t *fp;
char errbuf[PCAP_ERRBUF_SIZE];
u_char *packet[]; // I will need to allocate it at runtime, because packets will be diffrent sizes i suppose



// Data of service
struct service {
	DWORD dwLocalAddr;
	DWORD dwLocalPort;
	DWORD dwRemoteAddr;
	DWORD dwRemotePort;
};

/*struct eth_hdr {
	u_char source[6];
	u_char destination[6];
	u_char type[2];
};

struct ip_hdr{
	WORD ver;
	WORD ihl;
	DWORD tos;

};*/

service *lServ; // local ip struct
service *rServ; // remote ip struct

in_addr ip_hdr;

// netstat -aon | findstr <port>
// tasklist /svc /FI "PID eq <pid from netstat>"
// getservbyport ??

int main()
{
	memset(&szLocalAddr, '\0', ADDR_SIZE);
	memset(&szRemoteAddr, '\0', ADDR_SIZE);

	lServ = new service;
	rServ = new service;

	// Load Npcap and its functions. 
	if (!LoadNpcapDlls()) {
		fprintf(stderr, "[!] Couldn't load Npcap\n");
		system("pause");
		exit(1);
	}

	// All devices
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);
	}

	// Scan the list printing every entry 
	for (d = alldevs; d; d = d->next)
	{
		nDevs++;
		ifprint(d);
	}

	while (true) {
		printf("Choose internet adapter in use: ");
		scanf_s("%d", &nDev);

		if (nDev <= nDevs)
			break;
		printf("Wrong device! %d\n", nDev);
	}

	// Choosing adapter
	d = alldevs;
	for (; nDev; nDev--)
	{
		d = d->next;
	}

	pcap_freealldevs(alldevs); // free alldevs, it's no longer in use

	// Show and choose service
	show_services(); // TODO: show pid and process name and not ip

	// Open adapter
	if ((fp = pcap_open(d->name, 65535, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL) {
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
	}

	*packet = new u_char[20]; // only header for now
	

	system("pause");

	free(fp);
	free(lServ);
	return 0;
}


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

// show established connections
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

			nServices = i-2;

			if (pTcpTable->table[i].dwState != MIB_TCP_STATE_ESTAB) { continue; }

			printf("\n\tTCP[%d] State: %ld - ", i, pTcpTable->table[i].dwState);
			printf("ESTABLISHED\n");

			IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwLocalAddr;
			InetNtop(AF_INET, &IpAddr.S_un.S_addr, (PSTR)szLocalAddr, 128);
			remove_null(szLocalAddr);
			printf("\tTCP[%d] Local Addr: %s\n", i, szLocalAddr);

			printf("\tTCP[%d] Local Port: %d \n", i,
				ntohs((u_short)pTcpTable->table[i].dwLocalPort));

			IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwRemoteAddr;
			InetNtop(AF_INET, &IpAddr, (PSTR)szRemoteAddr, 128);
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

		while (true) {
			printf("\n[*] Choose service (%d): ", nServices);
			scanf_s("%d", &nService);

			if (nService <= nServices)
				break;
			printf("Wrong service! %d\n", nService);
		}

		// put choosen service into struct
		lServ->dwLocalAddr = pTcpTable->table[nService].dwLocalAddr;
		lServ->dwLocalPort = pTcpTable->table[nService].dwLocalPort;
		lServ->dwRemoteAddr = pTcpTable->table[nService].dwRemoteAddr;
		lServ->dwRemotePort = pTcpTable->table[nService].dwRemotePort;

		printf("\n[+] %s\n", iptos(lServ->dwLocalAddr));
		printf("[+] %d\n", htons(lServ->dwLocalPort));
		printf("[+] %s\n", iptos(lServ->dwRemoteAddr));
		printf("[+] %d\n", htons(lServ->dwRemotePort));

		FREE(pTcpTable);
		pTcpTable = NULL;
	}
}

// send packet
int send_packet(u_char *packet[]) {

	pcap_sendpacket(fp, *packet, sizeof(packet));

	return 0;
}

// load npcap dlls
BOOL LoadNpcapDlls()
{
	TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, TEXT("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}

	printf("[*] Loading libraries complete!\n");

	return TRUE;
}

// print interfaces from pcap
void ifprint(pcap_if_t *d)
{
	pcap_addr_t *a;
	static int i = 0;


	if (d->description) {
		printf("[%2d] %s", i, d->description);
		i++;
	}

	// IP addresses 
	for (a = d->addresses; a; a = a->next) {
		printf("\tAddress Family: #%d\n", a->addr->sa_family);
		switch (a->addr->sa_family)
		{
		case AF_INET:
			printf("\tAddress Family Name: AF_INET\n");
			if (a->addr)
				printf("\tAddress: %s\n", iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
			if (a->netmask)
				printf("\tNetmask: %s\n", iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
			if (a->broadaddr)
				printf("\tBroadcast Address: %s\n", iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
			if (a->dstaddr)
				printf("\tDestination Address: %s\n", iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
			break;
		case AF_INET6:
			printf("\tAddress: IPv6");
			break;
		default:
			printf("\tAddress Family Name: Unknown\n");
			break;
		}
	}
	printf("\n");
}

// From tcptraceroute, convert a numeric IP address to a string 
#define IPTOSBUFFERS	12
char *iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	_snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}