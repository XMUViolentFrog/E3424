/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies 
 * nor the names of its contributors may be used to endorse or promote 
 * products derived from this software without specific prior written 
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif
#include "pcap.h"
FILE* fp;
/* 4 bytes IP address */
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
}mac_address;
typedef struct Port_no
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}Port_no;
typedef struct EthernetII
{
	mac_address dst_addr;
	mac_address src_addr;
	u_char type_4[2];
}E_header;
/* IPv4 header */
typedef struct ip
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
	u_int	op_pad;			// Option + Padding
}ip_header;
typedef struct tcp
{
	Port_no src_port;
	Port_no dst_port;
	Port_no Seq_number;
	Port_no Ack_number;
	u_char head_length;
	u_char Flags[2];
	u_char wsz[2];
	u_char Checksum[2];
	u_char UP[2];
}tcp_head;
typedef struct FTP_head
{
	u_char cmd[100];
}FTP_head;
/*
typedef struct FTP_id
{
	u_short id1;
	u_short id2;
	u_short id3;
	u_short id4;
}FTP_command;
typedef struct FTP
{
	FTP_command command;
}FTP;
*/
/* UDP header*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;


/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


int main()
{
	

	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "tcp";
	struct bpf_program fcode;
	
	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	/* Print the list */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	
	printf("Enter the interface number (1-%d):",i);
	scanf("%d", &inum);
	
	/* Check if the user specified a valid adapter */
	if(inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");
		
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	
	/* Open the adapter */
	if ((adhandle= pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/* Check the link layer. We support only Ethernet for simplicity. */
	if(pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	if(d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask=0xffffff; 


	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
	{
		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	//set the filter
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr,"\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	printf("\nlistening on %s...\n", d->description);
	
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	
	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);
	
	return 0;
}

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	fp = fopen("Log.csv", "at");
	struct tm* ltime;
	char timestr[80];
	ip_header* ih;
	udp_header* uh;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;
	E_header* Eh;
	FTP_head* Fh;
	int index_fh;

	/*
	 * unused parameter
	 */
	(VOID)(param);
	Eh = (E_header*)(pkt_data);
	/* retireve the position of the ip header */
	ih = (ip_header*)(pkt_data +14); //length of ethernet header
	Fh = (ip_header*)(pkt_data +54);

	if (Fh->cmd[0] == 'U' && Fh->cmd[1] == 'S' && Fh->cmd[2] == 'E' && Fh->cmd[3] == 'R')
	{
		/* convert the timestamp to readable format */
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", ltime);
		/* print timestamp and length of the packet */
		fprintf(fp,"%s,", timestr);
		fprintf(fp,"%02x-%02x-%02x-%02x-%02x-%02x,%d.%d.%d.%d,%02x-%02x-%02x-%02x-%02x-%02x,%d.%d.%d.%d,",
			Eh->src_addr.byte1,
			Eh->src_addr.byte2,
			Eh->src_addr.byte3,
			Eh->src_addr.byte4,
			Eh->src_addr.byte5,
			Eh->src_addr.byte6,
			ih->saddr.byte1,
			ih->saddr.byte2,
			ih->saddr.byte3,
			ih->saddr.byte4,
			Eh->dst_addr.byte1,
			Eh->dst_addr.byte2,
			Eh->dst_addr.byte3,
			Eh->dst_addr.byte4,
			Eh->dst_addr.byte5,
			Eh->dst_addr.byte6,
			ih->daddr.byte1,
			ih->daddr.byte2,
			ih->daddr.byte3,
			ih->daddr.byte4
			);
		index_fh = 5;
		while (1) 
		{
			if ((Fh->cmd[index_fh]) ==(char)(13))
			{
				fprintf(fp, ",");
				fclose(fp);
				return;
			}
			else
			{
				fprintf(fp, "%c", Fh->cmd[index_fh]);
				index_fh++;
			}
		}
	}
	if (Fh->cmd[0] == 'P' && Fh->cmd[1] == 'A' && Fh->cmd[2] == 'S' && Fh->cmd[3] == 'S')
	{
		index_fh = 5;
		while (1)
		{
			if ((Fh->cmd[index_fh]) == (char)(13))
			{
				fprintf(fp, ",");
				printf("ÕýÔÚÐ´Èë...\n");
				fclose(fp);
				return;
			}
			else
			{
				fprintf(fp, "%c", Fh->cmd[index_fh]);
				index_fh++;
			}
		}
	}
	if (Fh->cmd[0] == '2' && Fh->cmd[1] == '3' && Fh->cmd[2] == '0')
	{
		fprintf(fp, "SUCCEED\n");
	}
	if (Fh->cmd[0] == '5' && Fh->cmd[1] == '3' && Fh->cmd[2] == '0')
	{
		fprintf(fp, "FAILED\n");
	}
	/* retireve the position of the udp header 
	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header*)((u_char*)ih + ip_len);

	/* convert from network byte order to host byte order 
	sport = ntohs(uh->sport);
	dport = ntohs(uh->dport);

	/* print ip addresses and udp ports */
	/*printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		sport,
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4,
		dport);*/
	//printf("\n");
	fclose(fp);
}