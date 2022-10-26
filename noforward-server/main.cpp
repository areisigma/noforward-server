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
int forge_packet(u_char*);

int fill_mac(pcap_if_t*, u_char[]);
//int fill_ip();
//int fill_tcp();

BOOL LoadNpcapDlls();
void ifprint(pcap_if_t*);
char *iptos(u_long);
char *iptos(u_long, bool);


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



// Data of service
struct service {
	DWORD dwLocalAddr;
	DWORD dwLocalPort;
	DWORD dwRemoteAddr;
	DWORD dwRemotePort;
};

/*
// 14 bytes
struct eth_hdr {
	u_char source[6];
	u_char destination[6];
	u_short type;
};

// 20 bytes
struct ip_hdr{
	ULONG ip_src_addr;
	ULONG ip_dst_addr;
	u_char ip_ver_hdr_len;
	u_char ip_tos;
	u_short ip_len;
	u_short ip_id;
	u_short ip_chksum;
	u_short ip_frag_offset;
	u_char ip_ttl;
	u_char ip_type;
};

// 20 bytes
struct tcp_hdr {
	u_short tcp_src_port;
	u_short tpc_dst_port;
	u_int tcp_seq;
	u_int tcp_ack;
	u_char reserved : 4;
	u_char tcp_offset : 4;
	u_char tcp_flags;
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PUSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
	u_short tcp_window;
	u_short tcp_chksum;
	u_short tcp_urgent;
};
*/

service *lServ; // local service info struct
service *rServ; // remote service info struct // propably this will gonna be a array for clients

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

	// Open adapter; i haven't seen packet bigger than 800 bytes, so 2000 bytes are far more than i need
	if ((fp = pcap_open(d->name, 2048, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL) {
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
	}

	// Dynamic array, now i have undefined length of array so it's "unlimited"
	u_char *packet = new u_char[65535];
	memset(packet, '\0', sizeof(packet));

	forge_packet(packet);


	delete packet;
	system("pause");
	return 0;
}


// removes null bytes from array
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

// shows established connections
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
			printf("\n[$] Choose service (%d): ", nServices);
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
		printf("[+] %d\n\n", htons(lServ->dwRemotePort));

		FREE(pTcpTable);
		pTcpTable = NULL;
	}
}

int compare_guid(wchar_t *wszPcapName, wchar_t *wszIfName)
{
	wchar_t *pc, *ic;

	// Find first { char in device name from pcap
	for (pc = wszPcapName; ; ++pc)
	{
		if (!*pc)
			return -1;

		if (*pc == L'{') {
			pc++;
			break;
		}
	}

	// Find first { char in interface name from windows
	for (ic = wszIfName; ; ++ic)
	{
		if (!*ic)
			return 1;

		if (*ic == L'{') {
			ic++;
			break;
		}
	}

	// See if the rest of the GUID string matches
	for (;; ++pc, ++ic)
	{
		if (!pc)
			return -1;

		if (!ic)
			return 1;

		if ((*pc == L'}') && (*ic == L'}'))
			return 0;

		if (*pc != *ic)
			return *ic - *pc;
	}
}

// gets mac of NIC from GetIfTable
int find_local_mac(u_char mac_addr[6]) {
	// Declare and initialize variables.

	wchar_t* wszWideName = NULL;

	DWORD dwSize = 0;
	DWORD dwRetVal = 0;

	int nRVal = 0;

	unsigned int i;


	/* variables used for GetIfTable and GetIfEntry */
	MIB_IFTABLE *pIfTable;
	MIB_IFROW *pIfRow;

	// Allocate memory for our pointers.
	pIfTable = (MIB_IFTABLE *)malloc(sizeof(MIB_IFTABLE));
	if (pIfTable == NULL) {
		return 0;
	}
	// Make an initial call to GetIfTable to get the
	// necessary size into dwSize
	dwSize = sizeof(MIB_IFTABLE);
	dwRetVal = GetIfTable(pIfTable, &dwSize, FALSE);

	if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
		free(pIfTable);
		pIfTable = (MIB_IFTABLE *)malloc(dwSize);
		if (pIfTable == NULL) {
			return 0;
		}

		dwRetVal = GetIfTable(pIfTable, &dwSize, FALSE);
	}

	if (dwRetVal != NO_ERROR)
		goto done;

	// Convert input pcap device name to a wide string for compare
	{
		size_t stISize, stOSize;

		stISize = strlen(d->name) + 1;

		wszWideName = (wchar_t*)malloc(stISize * sizeof(wchar_t));

		if (!wszWideName)
			goto done;

		mbstowcs_s(&stOSize, wszWideName, stISize, d->name, stISize);
	}

	for (i = 0; i < pIfTable->dwNumEntries; i++) {
		pIfRow = (MIB_IFROW *)& pIfTable->table[i];

		if (!compare_guid(wszWideName, pIfRow->wszName)) {
			if (pIfRow->dwPhysAddrLen != 6)
				continue;

			memcpy(mac_addr, pIfRow->bPhysAddr, 6);
			nRVal = 1;
			break;
		}
	}

done:
	if (pIfTable != NULL)
		free(pIfTable);
	pIfTable = NULL;

	if (wszWideName != NULL)
		free(wszWideName);
	wszWideName = NULL;

	return nRVal;
}

int print_arp_error(int ret) {

	switch (ret) {
	case ERROR_BAD_NET_NAME:
		printf("\tERROR_BAD_NET_NAME\n");
		break;
	case ERROR_BUFFER_OVERFLOW:
		printf("\tERROR_BUFFER_OVERFLOW\n");
		break;
	case ERROR_GEN_FAILURE:
		printf("\tERROR_GEN_FAILURE\n");
		break;
	case ERROR_INVALID_PARAMETER:
		printf("\tERROR_INVALID_PARAMETER\n");
		break;
	case ERROR_INVALID_USER_BUFFER:
		printf("\tERROR_INVALID_USER_BUFFER\n");
		break;
	case ERROR_NOT_FOUND:
		printf("\tERROR_NOT_FOUND\n");
		break;
	case ERROR_NOT_SUPPORTED:
		printf("\tERROR_NOT_SUPPORTED\n");
		break;
	default:

		break;
	}

	return 0;
}

// sends ARP to router to gather it's mac address
int find_router_mac(u_char out[6]) {

	IPAddr rAddr = 0;
	char dtAddr[15]; // dotted router ip address
	in_addr *rAddrStruct = new in_addr;
	u_char mac[6];
	u_long macLen = 6;

	memset(&dtAddr, '\0', sizeof(dtAddr));
	memcpy(&dtAddr, iptos(lServ->dwLocalAddr, true), 3 * 4 + 3);

	if (dtAddr == NULL) {

		printf("[!] Local IP address not found!\n");
		return 0;
	}

	//printf("[*] Router IP: %s\n", dtAddr);

	if (inet_pton(AF_INET, (PCSTR) dtAddr, rAddrStruct) != 1) {
		printf("[!] Error while converting router address!\n");
		return 0;
	}
	
	rAddr = rAddrStruct->S_un.S_addr;

	//printf("[*] rAddr: %d\n    lAddr: %d\n", rAddr, lServ->dwLocalAddr);

	int iRet = SendARP(rAddr, (IPAddr)lServ->dwLocalAddr, mac, &macLen);
	if(iRet != NO_ERROR) {

		printf("[!] Obtaining router mac address failed!\n");
		print_arp_error(iRet);
		return 0;
	}

	//printf("[+] Router MAC: %x:%x:%x:%x:%x:%x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	memcpy(out, mac, sizeof(mac));

	delete rAddrStruct;

	return 1;
}

// fills packet with mac addresses and moves offset by length of mac address
int fill_mac(u_char *packet, u_char mac[], const char *dest, int offset) {

	for (int i = 0; i <  6; i++) {
		packet[i + offset] = mac[i];
	}

	printf("[*] %s MAC: %x:%x:%x:%x:%x:%x\n", dest, packet[0+offset],
													packet[1 + offset],
													packet[2 + offset],
													packet[3 + offset],
													packet[4 + offset],
													packet[5 + offset]);

	return 0;
}

// puts mac addresses, ips, tcp things into packet
int forge_packet(u_char *packet) {

	int offset = 0; // local packet offset

	// MAC variables
	u_char srcMac[6];
	u_char dstMac[6];

	// IP variables


	// MAC functions
	memset(&srcMac, '\0', 6);
	memset(&dstMac, '\0', 6);

	find_local_mac(srcMac);
	fill_mac(packet, srcMac, "Source", offset); offset += 6;

	if (find_router_mac(dstMac) == 0) {
		printf("[!] Error while finding router mac!\n");
		return 0;
	}
	fill_mac(packet, dstMac, "Destination", offset); offset += 6;

	// Type 0x8000 (IPv4)
	offset++;
	packet[offset] = 0x80;
	offset++;
	packet[offset] = 0x00;

	// IP Functions

	// Version 4 and DSF(?)
	offset++;
	packet[offset] = 0x45;
	offset++;
	packet[offset] = 0x00;



	return 1;
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

// router ip option
char *iptos(u_long in, bool isRouter)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);

	if(isRouter)
		_snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]), "%d.%d.%d.1", p[0], p[1], p[2]);
	else
		_snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);

	for (int i = 0; i < 20; i++) {
		if (output[which][i] == '\0')
			memset(&output[which][i], '\0', 3);
	}

	return output[which];
}