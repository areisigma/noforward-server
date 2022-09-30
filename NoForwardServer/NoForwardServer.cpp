//1. Show available services to steal a connection
//2. Packet forgery
	//a. Encapsulate original packet
//3. Listen on choosen service for forged packet
//4. Proxy to forward packets in OS

#pragma comment(lib,  "ws2_32.lib")

#include <iostream>
#include <Windows.h>
#include <winsock.h>
#include <tchar.h>
#include <stdio.h>

#include "pcap.h"

int showServices();
int forgePacket();
int listenService();
int decapPacket();
int forwardPacket();


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
	return TRUE;
}


int main()
{
	// Load Npcap and its functions. 
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "[!] Couldn't load Npcap\n");
		system("pause");
		exit(1);
	}

	if (pcap_findalldevs()) {

	}


}

int showServices() {

}

int forgePacket() {

}

int listenService() {

}

int decapPacket() {

}

int forwardPacket() {

}