#define _CRT_SECURE_NO_WARNINGS
#define TRAFFIC_WARNING 1024*1024*1
#define INTERVAL 5
#include <WinSock2.h>
#include "pcap.h"
#include <iostream>
#include <fstream>
#include <conio.h>
using namespace std;
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;
typedef struct mac_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
};
typedef struct ip_header
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ip_address saddr; // Source address 
	ip_address daddr; // Destination addres
	u_int	op_pad;			// Option + Padding
}ip_header;
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;
typedef struct mac_header
{
	mac_address dest_addr;
	mac_address src_addr;
	u_char type[2];
} mac_header;
typedef struct ip_mac_address
{
	ip_address ip; 
	mac_address mac;
}
ip_mac_address;
class IPNode
{
private:
	ip_mac_address nodeAddress;
	long Len;
public:
	IPNode* pNext;
	IPNode(ip_mac_address Address)
	{
		nodeAddress = Address;
		Len = 0;
	}
	void addLen(long len)
	{
		Len += len;
	}
	long getLen()
	{
		return Len;
	}
	//����IP��ַ
	ip_mac_address getAddress()
	{
		return nodeAddress;
	}

};
time_t beg;
class NodeList
{
	IPNode* pHead;
	IPNode* pTail;
public:
	NodeList()
	{
		pHead = pTail = NULL;
	}
	~NodeList()
	{
		if (pHead != NULL)
		{
			IPNode* pTemp = pHead;
			pHead = pHead->pNext;
			delete  pTemp;
		}
	}
	void addNode(ip_mac_address Address, long len)
	{
		IPNode* pTemp;
		if (pHead == NULL)
		{
			pTail = new IPNode(Address);
			pHead = pTail;
			pTail->pNext = NULL;
		}
		else
		{
			pTemp = pHead;
			while (1)
			{
				ip_mac_address tempAddress = pTemp->getAddress();
				if (tempAddress.mac.byte1 == Address.mac.byte1 && tempAddress.mac.byte2 == Address.mac.byte2 && tempAddress.mac.byte3 == Address.mac.byte3 && tempAddress.mac.byte4 == Address.mac.byte4 && tempAddress.mac.byte5 == Address.mac.byte5 && tempAddress.mac.byte6 == Address.mac.byte6 &&tempAddress.ip.byte1 == Address.ip.byte1 && tempAddress.ip.byte2 == Address.ip.byte2 && tempAddress.ip.byte3 == Address.ip.byte3 && tempAddress.ip.byte4 == Address.ip.byte4)
				{
					pTemp->addLen(len);
					break;
				}
				if (pTemp->pNext == NULL)
				{
					pTail->pNext = new IPNode(Address);
					pTail = pTail->pNext;
					pTail->addLen(len);
					pTail->pNext = NULL;
					break;
				}
				pTemp = pTemp->pNext;
			}
		}
	}
	void clearList()
	{
		IPNode* p, *q;
		p = pHead->pNext;
		while (p)
		{
			q = p->pNext;
			free(p);
			p = q;
		}
		pHead = NULL;
	}
	ostream& print(ostream& os)
	{
		os <<"\n"<<INTERVAL<<" seconds\n";
		os << "MACaddress," << "IPaddress," << "Len\n";
		IPNode* pTemp = pHead;
		while (pTemp)
		{
			ip_mac_address lTemp = pTemp->getAddress();
			os <<hex<<uppercase<<int(lTemp.mac.byte1) << "-" << int(lTemp.mac.byte2) << "-" << int(lTemp.mac.byte3) << "-" << int(lTemp.mac.byte4) << "-" << int(lTemp.mac.byte5)<< "-" << int(lTemp.mac.byte6)<< ",";
			os <<dec<<int(lTemp.ip.byte1) << "-" << int(lTemp.ip.byte2) << "-" << int(lTemp.ip.byte3) << "-" << int(lTemp.ip.byte4) << ",";
			os <<pTemp->getLen() << endl;
			pTemp = pTemp->pNext;
		}
		clearList();
		return os;
	}
};
NodeList sourceLink;
NodeList destLink;
long totalLen;
/* IPv4 header */

/* prototype of the packet handler */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

#define FROM_NIC
int main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "ip and udp";
	struct bpf_program fcode;
#ifdef FROM_NIC
	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);
	/* Check if the user specified a valid adapter */
	if (inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");

		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture. 
					   // 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Check the link layer. We support only Ethernet for simplicity. */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;


	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	time(&beg);            //��õ�ǰʱ��
	FILE* log;
	freopen_s(&log, "Log\\log.csv", "wb", stdout);
	printf("date,time,srcMAC,srcIP,destMAC,destIP,len\n");
	fclose(log);
	FILE* srcLog;
	freopen_s(&srcLog, "Log\\srcLog.csv", "wb", stdout);
	printf("srcLog\n");
	fclose(srcLog);
	FILE* destLog;
	freopen_s(&destLog, "Log\\destLog.csv", "wb", stdout);
	printf("destLog\n");
	fclose(destLog);
	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);

#else
	/* Open the capture file */
	if ((adhandle = pcap_open_offline("C:\\Users\\Hasee\\Desktop\\dns.pcap",			// name of the device
		errbuf					// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the file %s.\n");
		return -1;
	}

	/* read and dispatch packets until EOF is reached */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	pcap_close(adhandle);
#endif
	return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	struct tm* ltime;
	char timestr[16];
	mac_header* mh;
	ip_header* ih;
	ip_mac_address sim;
	ip_mac_address dim;
	udp_header* uh;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;
	int length = sizeof(mac_header) + sizeof(ip_header);
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	mh = (mac_header*)pkt_data;
	ih = (ip_header*)(pkt_data + sizeof(mac_header));
	sim.ip = ih->saddr;
	sim.mac = mh->src_addr;
	dim.ip = ih->daddr;
	dim.mac = mh->dest_addr;
	FILE* log;
	freopen_s(&log, "Log\\log.csv", "ab", stdout);
	printf("%d-%d-%d,", 1900 + ltime->tm_year, 1 + ltime->tm_mon, ltime->tm_mday);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
	printf("%s,", timestr);
	printf("%02X-", mh->src_addr.byte1);
	printf("%02X-", mh->src_addr.byte2);
	printf("%02X-", mh->src_addr.byte3);
	printf("%02X-", mh->src_addr.byte4);
	printf("%02X-", mh->src_addr.byte5);
	printf("%02X", mh->src_addr.byte6);
	printf(",");
	printf("%d-%d-%d-%d",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4
	);
	printf(",");
	printf("%02X-", mh->dest_addr.byte1);
	printf("%02X-", mh->dest_addr.byte2);
	printf("%02X-", mh->dest_addr.byte3);
	printf("%02X-", mh->dest_addr.byte4);
	printf("%02X-", mh->dest_addr.byte5);
	printf("%02X", mh->dest_addr.byte6);
	printf(",");
	printf("%d-%d-%d-%d",
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4);
	printf(",");
	printf("%d", header->len);
	printf("\n");
	sourceLink.addNode(sim, header->len);
	destLink.addNode(dim, header->len);
	freopen("CON", "w", stdout);
	totalLen += header->len;
	if (totalLen >= TRAFFIC_WARNING)
		cout << "Warning:Traffic over "<<TRAFFIC_WARNING/1024/1024<<" MB!\n";
	if (local_tv_sec - beg >= INTERVAL)
	{
		FILE* srcLog;
		freopen_s(&srcLog, "Log\\srcLog.csv", "ab", stdout);
		sourceLink.print(cout);
		FILE* destLog;
		freopen_s(&destLog, "Log\\destLog.csv", "ab", stdout);
		destLink.print(cout);
		//cout << "srcIP:";
		//sourceLink.print(cout);
		//cout << "destIP:";
		//destLink.print(cout);
		fclose(srcLog);
		fclose(destLog);
		beg = local_tv_sec;
	}
	fclose(log);
	if ((_kbhit() && _getch() == 0x1b))
		exit(0);
}