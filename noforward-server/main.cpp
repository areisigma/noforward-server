#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <tchar.h>
#include <string.h>
#include <thread>

#include "pcap.h"

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))
#define ADDR_SIZE 128
#define PACKET_SIZE 1000

int remove_null(char[]);
int show_services();
int forge_packet_header(u_char*);

//int fill_mac(pcap_if_t*, u_char[]);
//int fill_ip();
//int fill_tcp();

BOOL LoadNpcapDlls();
void ifprint(pcap_if_t*);
char *iptos(u_long);
char *iptos(u_long, bool);
int stohi(char *);

// for stohi
union
{
	unsigned int integer;
	unsigned char byte[4];
} itoch;

// services
PMIB_TCPTABLE pTcpTable;
DWORD dwSize = 0;
DWORD dwRetVal = 0;

// for show_services() purpose
struct in_addr IpAddr;
char szLocalAddr[ADDR_SIZE];
char szRemoteAddr[ADDR_SIZE];
u_int nServices;
u_int nService;

// pcap devs
pcap_if_t *alldevs;
pcap_if_t *d;
u_int nDevs = 0;
u_int nDev;

// pcap socket handler
pcap_t *fp;
char errbuf[PCAP_ERRBUF_SIZE];

// Data of service
struct service {
	DWORD dwLocalAddr;
	DWORD dwLocalPort;
	DWORD dwRemoteAddr;
	DWORD dwRemotePort;
};

service *lServ; // local service info struct
service *rServ; // remote service info struct // propably this will gonna be a array for clients // nope, every thread will have its own

// netstat -aon | findstr <port>
// tasklist /svc /FI "PID eq <pid from netstat>"
// getservbyport ??

int main()
{
	char type;

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
	
	printf("Client/Server [C/S] > ");
	scanf_s("%c", &type);
	printf("[+] %s\n", type == 'S' ? "Server" : "Client");

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
		printf("Choose internet adapter in use > ");
		scanf_s("%d", &nDev); // normally delete the commentation
		//nDev = 5;

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
	if ((fp = pcap_open(d->name, 1000, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL) {
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
	}


	u_char packet[PACKET_SIZE];// = new u_char[1000];
	memset(&packet, '\0', PACKET_SIZE);
	

	/*
	Yeah, i think i could listen for packets
	in main function and then while listening
	on a chosen device, start a new thread
	that handles client (who send prefabicated
	packet to server).
	Thus forge_packet() will ran only in threads,
	nor in main function.
	*/

	if (type == 'C') {
		char servAddr[3 * 4 + 3 + 1];
		
		memset(&servAddr, '\0', 3 * 4 + 3 + 1);

		// "Local"
		printf("Enter client's service address > ");
		scanf_s("%s", servAddr, 3 * 4 + 3 + 1); rServ->dwLocalAddr = stohi(servAddr);
		printf("Enter client's service port > ");
		scanf_s("%d", &rServ->dwLocalPort, 5);

		memset(&servAddr, '\0', 3 * 4 + 3 + 1);

		// "Remote"
		printf("Enter client's address > ");
		scanf_s("%s", servAddr, 3 * 4 + 3 + 1); rServ->dwRemoteAddr = stohi(servAddr);
		printf("Enter client's port > ");
		scanf_s("%d", &rServ->dwRemoteAddr, 5);

		delete servAddr;
	}

	if (forge_packet_header(packet) == 0) {
		printf("[!] Error while forging packet!\n");
		return 0;
	}

	if (pcap_sendpacket(fp, packet, 100 /* size */) != 0) // Size will be set for every packet, so there won't be any additional zeros
	{
		fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(fp));
		return 0;
	}

	// multithreading to handle clients

	//delete packet;
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

			memset(&szLocalAddr, '\0', ADDR_SIZE);
			memset(&szRemoteAddr, '\0', ADDR_SIZE);
		}
	}
	else {
		printf("\tGetTcpTable failed with %d\n", dwRetVal);
		FREE(pTcpTable);
		return 1;
	}

	if (pTcpTable != NULL) {

		while (true) {
			printf("\n[$] Choose service (%d) > ", nServices);
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

// idk
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

// prints error
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

	return 1;
}

// fills packet with ip address
int fill_ip_addr(u_char *packet, DWORD ip, int offset) {

	char dtAddr[15]; // dotted router ip address
	in_addr *rAddrStruct = new in_addr;

	memcpy(&dtAddr, iptos(ip), 3 * 4 + 3);

	if (inet_pton(AF_INET, (PCSTR)dtAddr, rAddrStruct) != 1) {
		printf("[!] Error while converting router address!\n");
		return 0;
	}

	
	packet[offset] = rAddrStruct->S_un.S_un_b.s_b1; // 1st octect
	offset++;
	packet[offset] = rAddrStruct->S_un.S_un_b.s_b2; // 2nd octet
	offset++;
	packet[offset] = rAddrStruct->S_un.S_un_b.s_b3; // 3rd octet
	offset++;
	packet[offset] = rAddrStruct->S_un.S_un_b.s_b4; // 4th octet
	offset++;

	printf("[+] %d.%d.%d.%d\n", packet[offset -4], packet[offset -3], packet[offset -2], packet[offset -1]);

	delete rAddrStruct;

	return 1;
}

// ip header checksum algorithm
uint16_t ip_checksum(void* vdata, size_t length, int sumOffset) {
	// Cast the data pointer to one that can be indexed.
	char* data = (char*)vdata;

	// Initialise the accumulator.
	uint32_t acc = 0xffff;
	uint32_t bcc = 0x0000;

	char *out = new char[2];
	memset(out, '\0', 2);

	// Handle complete 16-bit blocks.
	for (size_t i = 0; i + 1 < length; i += 2) {
		uint16_t word;
		memcpy(&word, data + i, 2);
		acc += ntohs(word);
		if (acc > 0xffff) {
			acc -= 0xffff;
		}
	}

	// Handle any partial block at the end of the data.
	if (length & 1) {
		uint16_t word = 0;
		memcpy(&word, data + length - 1, 1);
		acc += ntohs(word);
		if (acc > 0xffff) {
			acc -= 0xffff;
		}
	}

	bcc = htons(~acc);
	memcpy(out, &bcc, 2);

	data[sumOffset] = out[0]; // it may be wrong endianness idk
	data[sumOffset + 1] = out[1];


	delete out;

	// Return the checksum in network byte order.
	return htons(~acc);
}

// handles the ip header in packet // ADD SERVICE
int fill_ip(u_char *packet, int offset, int ipLenOffset, int ipChkSumOffset) {

	// Type 0x0800 (IPv4)
	packet[offset] = 0x08;
	offset++;
	packet[offset] = 0x00;
	offset++;

	// Version 4 and DSF(?)
	packet[offset] = 0x45;
	offset++;
	packet[offset] = 0x00;
	offset++;

	// 2 bytes of total length, fill later
	packet[offset] = 0x00; ipLenOffset = offset;
	offset++;
	packet[offset] = 0x00;
	offset++;

	// IP identifier
	packet[offset] = 0x12;
	offset++;
	packet[offset] = 0x34;
	offset++;

	// Flags
	packet[offset] = 0x00;
	offset++;
	packet[offset] = 0x00;
	offset++;

	// TTL 128
	packet[offset] = 0x80;
	offset++;

	// Proto TCP
	packet[offset] = 0x06;
	offset++;

	// Header Checksum TODO
	packet[offset] = 0x00; ipChkSumOffset = offset;
	offset++;
	packet[offset] = 0x00;
	offset++;

	// Spoof here
	// Source IP
	if (fill_ip_addr(packet, lServ->dwLocalAddr, offset) == 0) { // client's service
		printf("[!] Error while filling source ip!\n");
		return 0;
	}
	offset += 4;

	// Destination IP
	if (fill_ip_addr(packet, lServ->dwRemoteAddr, offset) == 0) { // client's network
		printf("[!] Error while filling destination ip!\n");
		return 0;
	}
	offset += 4;

	//ip_checksum(packet, offset, ipChkSum); // propably i dont need to use it


	return offset;
}

// fills port window with port
int fill_tcp_port(u_char *packet, int port, int offset) {

	int networkPort = htons(port);

	memcpy(packet + offset, &networkPort, 2);

	return 1;
}

// handles the tcp header in packet // ADD SERVICE
int fill_tcp(u_char *packet, int offset) {

	// Source Port
	if (fill_tcp_port(packet, 42069, offset) == 0) { // remote port of client's service connection
		printf("[!] Error while filling tcp source port!\n");
		return 0;
	}
	offset += 2;

	// Dest Port
	if (fill_tcp_port(packet, 42069, offset) == 0) { // local port of client's service connection
		printf("[!] Error while filling tcp destination port!\n");
		return 0;
	}
	offset += 2;

	/*
	I don't have to bother about
	seq and ack numbers, because
	I will encapsulate packet,
	that does this for me.
	*/
	// Sequence number
	packet[offset] = 0x00;
	offset++;
	packet[offset] = 0x00;
	offset++;
	packet[offset] = 0x00;
	offset++;
	packet[offset] = 0x00;
	offset++;

	// Acknowledge number
	packet[offset] = 0x00;
	offset++;
	packet[offset] = 0x00;
	offset++;
	packet[offset] = 0x00;
	offset++;
	packet[offset] = 0x00;
	offset++;

	// Data offset and reserved bits; it's mostly 0x50 and sometimes 0x80
	packet[offset] = 0x50;
	offset++;

	// Flags
	/*packet[offset] = 0x00000000 | // Nonce							0x00000000
					 0x00000000 | // Congestion Window Reduced (CWR)	0x10000000
					 0x00000000 | // ECN-Echo							0x01000000
					 0x00000000 | // Urgent							0x00100000
					 0x00010000 | // Ack								0x00010000
					 0x00000000 | // Push								0x00001000
					 0x00000000 | // Reset								0x00000100
					 0x00000010 | // Syn								0x00000010
					 0x00000000;   // Fin								0x00000001*/
	//packet[offset] = 0x12; // SYN, ACK
	packet[offset] = 0x10; // ACK
	offset++;

	// Window Size; size of receive data (whatever that means)
	packet[offset] = 0x00;
	offset++;
	packet[offset] = 0x00;
	offset++;

	// Maybe this will be needed, but i dont think so, because of encapsulated packet
	// Checksum
	packet[offset] = 0x00;
	offset++;
	packet[offset] = 0x00;
	offset++;

	// Urgent pointer; i do not use URG flag, so this always will be set to 0x0
	packet[offset] = 0x00;
	offset++;
	packet[offset] = 0x00;
	offset++;

	return offset;
}

// puts mac addresses, ips, tcp things into packet
int forge_packet_header(u_char packet[PACKET_SIZE]) {

	int offset = 0; // local packet offset

	// MAC variables
	u_char srcMac[6];
	u_char dstMac[6];

	// IP variables
	int ipLenOffset = 0;
	int ipChkSumOffset = 0;

	//TCP variables


	// MAC
	// fill with zeros, us tin case
	memset(&srcMac, '\0', 6);
	memset(&dstMac, '\0', 6);

	// find local mac and put it in packet
	find_local_mac(srcMac);
	fill_mac(packet, srcMac, "Source", offset); offset += 6;

	// same thing with router's mac
	if (find_router_mac(dstMac) == 0) {
		printf("[!] Error while finding router mac!\n");
		return 0;
	}
	fill_mac(packet, dstMac, "Destination", offset); offset += 6;

	// I actually type of ethernet frame (IPv4) put into fill_ip(), but that does not matter so much
	// IP
	offset = fill_ip(packet, offset, ipLenOffset, ipChkSumOffset);
	if (offset == 0) {
		printf("[!] Error in ip!\n");
		return 0;
	}
	
	// TCP
	offset = fill_tcp(packet, offset);
	if (offset == 0) {
		printf("[!] Error in tcp!\n");
		return 0;
	}
	
	

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

// string to host integer
int stohi(char *ip) {
	char c;
	c = *ip;
	unsigned int integer;
	int val;
	int i, j = 0;
	for (j = 0; j < 4; j++) {
		if (!isdigit(c)) {  //first char is 0
			return (0);
		}
		val = 0;
		for (i = 0; i < 3; i++) {
			if (isdigit(c)) {
				val = (val * 10) + (c - '0');
				c = *++ip;
			}
			else
				break;
		}
		if (val < 0 || val>255) {
			return (0);
		}
		if (c == '.') {
			integer = (integer << 8) | val;
			c = *++ip;
		}
		else if (j == 3 && c == '\0') {
			integer = (integer << 8) | val;
			break;
		}

	}
	if (c != '\0') {
		return (0);
	}
	return (htonl(integer));
}