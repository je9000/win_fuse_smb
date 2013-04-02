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
#include "packets.h"
#include "checksums.h"

#ifdef _WIN32
#include <IPHlpApi.h>
#define snprintf _snprintf
#endif

#define IP_ADDR_LEN 4
#define IP_ADDR_STRING_FORMAT "%u.%u.%u.%u"
#define ETHER_ADDR_STRING_LEN (ETHER_ADDR_LEN * 2 + (ETHER_ADDR_LEN - 1) + 1)
#define ETHER_ADDR_STRING_FORMAT "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x"
#define ETHER_ADDR_STRING_SCAN_FORMAT "%x:%x:%x:%x:%x:%x"
#define PACKET_FILTER "ether dst host %s or ether broadcast or dst host %s"

#define OUR_MAC "0E:CD:FE:0D:38:DF"
#define OUR_IP "203.0.113.10"

#define REFLECT_PORT 445
#define REFLECT_TO_PORT 1445

typedef union ip_address {
	u_char		bytes[4];
	u_int32_t	addr;
} ip_address_numeric;

typedef struct {
	u_char	bytes[ETHER_ADDR_LEN];
	char	str[ETHER_ADDR_STRING_LEN];
} mac_address;

typedef struct {
	ip_address_numeric	num;
	char				str[16]; // strlen("123.123.123.123") + 1
} ip_address;

mac_address our_mac;
ip_address our_ip;

mac_address listen_mac;
ip_address listen_ip;

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, u_char *pkt_data);

void mac_from_string(char *str, u_char *bytes) {
	unsigned int i[6];
	sscanf(str, ETHER_ADDR_STRING_SCAN_FORMAT,
		&i[0],
		&i[1],
		&i[2],
		&i[3],
		&i[4],
		&i[5]
	);
	bytes[0] = i[0];
	bytes[1] = i[1];
	bytes[2] = i[2];
	bytes[3] = i[3];
	bytes[4] = i[4];
	bytes[5] = i[5];
}

void ip_from_string(char *str, u_char *bytes) {
	unsigned int i[4];
	sscanf(str, IP_ADDR_STRING_FORMAT,
		&i[0],
		&i[1],
		&i[2],
		&i[3]
	);
	bytes[0] = i[0];
	bytes[1] = i[1];
	bytes[2] = i[2];
	bytes[3] = i[3];
}

int get_mac(pcap_if_t *d, mac_address *m) {
	IP_ADAPTER_INFO *info = NULL, *pos;
    ULONG size = 0;
	char *windows_name;

	memcpy(our_mac.str, OUR_MAC, sizeof(OUR_MAC));
	mac_from_string(our_mac.str, our_mac.bytes);

	memcpy(our_ip.str, OUR_IP, sizeof(OUR_IP));
	ip_from_string(our_ip.str, (u_char *) &our_ip.num.bytes);

#define WINDOWS_NAME_PREFIX "\\Device\\NPF_"

	if (strlen(d->name) <= strlen(WINDOWS_NAME_PREFIX)) return 0;
	windows_name = d->name + strlen(WINDOWS_NAME_PREFIX);

    if (GetAdaptersInfo(info, &size) != ERROR_BUFFER_OVERFLOW) return 0;

    info = (IP_ADAPTER_INFO *) malloc(size);
	if (info == NULL) return 0;

    if (GetAdaptersInfo(info, &size) != ERROR_SUCCESS) return 0;

    for (pos = info; pos != NULL; pos = pos->Next) {
		if (strcmp(pos->AdapterName, windows_name) != 0) continue;
		if (pos->AddressLength != ETHER_ADDR_LEN) continue;
		memcpy(m->bytes, pos->Address, ETHER_ADDR_LEN);
		free(info);
		if (snprintf(m->str, sizeof(m->str), ETHER_ADDR_STRING_FORMAT,
			m->bytes[0],
			m->bytes[1],
			m->bytes[2],
			m->bytes[3],
			m->bytes[4],
			m->bytes[5]
		) >= sizeof(m->str) ) return 0;
		return 1;
    }

    free(info);
    return 0;
}

int get_ip(pcap_if_t *d, ip_address *ip) {
	pcap_addr_t *a;
	struct sockaddr_in *sin;
	for(a = d->addresses; a != NULL; a = a->next) {
		if (a->addr->sa_family != AF_INET) continue;
		sin = (struct sockaddr_in *) a->addr;
		memcpy(&ip->num.addr, &sin->sin_addr, sizeof(ip->num.addr));
		if (snprintf(ip->str, sizeof(ip->str), IP_ADDR_STRING_FORMAT,
			ip->num.bytes[0],
			ip->num.bytes[1],
			ip->num.bytes[2],
			ip->num.bytes[3]
		) >= sizeof(ip->str)) {
			return 0;
		}
		return 1;
	}
	return 0;
}

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *pcaph;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[128]; // Arbitrarily big
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
	//scanf("%d", &inum);
	inum = 1;
	
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
	if ((pcaph= pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 0,				// promiscuous mode (nonzero means promiscuous)
							 1,				// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/* Check the link layer. We support only Ethernet for simplicity. */
	if(pcap_datalink(pcaph) != DLT_EN10MB)
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

	if (!get_mac(d, &listen_mac) || !get_ip(d, &listen_ip)) {
		fprintf(stderr,"\nFailed to get interface MAC or IP address.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	pcap_freealldevs(alldevs);

	if (snprintf(packet_filter, sizeof(packet_filter), PACKET_FILTER, our_mac.str, our_ip.str)
		>= sizeof(packet_filter)
	) {
		fprintf(stderr,"\nsprintf error.\n");
		return -1;
	}

	//compile the filter
	if (pcap_compile(pcaph, &fcode, packet_filter, 1, netmask) <0 )
	{
		fprintf(stderr,"\nUnable to compile the packet filter: %s.\n", pcap_geterr(pcaph));
		return -1;
	}
	
	//set the filter
	if (pcap_setfilter(pcaph, &fcode) < 0)
	{
		fprintf(stderr,"\nError setting the filter: %s.\n", pcap_geterr(pcaph));
		return -1;
	}
	
	printf("\nlistening on %s (%s)...\n", our_ip.str, our_mac.str);
	
	/* start the capture */
	pcap_loop(pcaph, 0, packet_handler, (u_char *) pcaph);
	
	return 0;
}

// Woah! Checks ports in network byte order! Beware!
u_short check_reflect_dport(u_short port) {
	if (port == htons(REFLECT_PORT)) return htons(REFLECT_TO_PORT);
	return 0;
}

u_short check_reflect_sport(u_short port) {
	if (port == htons(REFLECT_TO_PORT)) return htons(REFLECT_PORT);
	return 0;
}

void make_eth_reply(struct ether_header *eth) {
	// Set Ethernet the destination to the source.
	memcpy(eth->ether_dhost, eth->ether_shost, sizeof(eth->ether_dhost));
	memcpy(eth->ether_shost, our_mac.bytes, sizeof(eth->ether_shost));
}

void make_ip_reply(struct ip *iph) {
	iph->ip_dst.S_un.S_addr = listen_ip.num.addr;
	iph->ip_src.S_un.S_addr = our_ip.num.addr;
}

void handle_arp(pcap_t *pcaph, u_char *pkt, bpf_u_int32 len) {
	struct ether_header *eth = (struct ether_header *) pkt;
	struct ether_arp *arp = (struct ether_arp *) (pkt + sizeof(struct ether_header));

	if (len < sizeof(struct ether_header) + sizeof(struct ether_arp)) return;

	// Pcap filter checks destination MAC for us.
	if (arp->ea_hdr.ar_op != htons(ARPOP_REQUEST) ||
		arp->ea_hdr.ar_pro != htons(ETHERTYPE_IP) ||
		arp->ea_hdr.ar_hln != ETHER_ADDR_LEN ||
		arp->ea_hdr.ar_pln != IP_ADDR_LEN
	) return;

	arp->ea_hdr.ar_op = htons(ARPOP_REPLY);
	
	make_eth_reply(eth);

	// Set ARP the destination to the source.
	memcpy(arp->arp_tha, arp->arp_sha, sizeof(arp->arp_tha));
	memcpy(arp->arp_tpa, arp->arp_spa, sizeof(arp->arp_tpa));

	// Fill in our info for the ARP source.
	memcpy(arp->arp_sha, our_mac.bytes, sizeof(arp->arp_tha));
	memcpy(arp->arp_spa, &our_ip.num.addr, sizeof(arp->arp_spa));

	pcap_sendpacket(pcaph, pkt, sizeof(struct ether_arp) + sizeof(struct ether_header));
}

void handle_tcp(pcap_t *pcaph, u_char *pkt, bpf_u_int32 len) {
	struct ether_header *eth = (struct ether_header *) pkt;
	struct ip *iph = (struct ip *) (pkt + sizeof(struct ether_header));
	struct tcphdr *tcp = (struct tcphdr *) (pkt + sizeof(struct ether_header) + sizeof(struct ip));
	u_short new_port;

	if ((new_port = check_reflect_dport(tcp->th_dport)))
		tcp->th_dport = new_port;
	else if ((new_port = check_reflect_sport(tcp->th_sport)))
		tcp->th_sport = new_port;
	else
		return;

	make_eth_reply(eth);
	make_ip_reply(iph);

	do_checksum((char *) iph, IPPROTO_TCP, len - sizeof(struct ether_header) - (iph->ip_hl * 4));
	do_checksum((char *) iph, IPPROTO_IP, iph->ip_hl * 4);

	pcap_sendpacket(pcaph, pkt, len);
}

void handle_ip(pcap_t *pcaph, u_char *pkt, bpf_u_int32 len) {
	struct ether_header *eth = (struct ether_header *) pkt;
	struct ip *ip = (struct ip *) (pkt + sizeof(struct ether_header));

	if (len < sizeof(struct ether_header) + sizeof(struct ip)) return;

	// Pcap filter checks destination IP and protocol version for us.
	if (ip->ip_p != IPPROTO_TCP) return;

	handle_tcp(pcaph, pkt, len);
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, u_char *pkt_data)
{
	struct ether_header *eth = (struct ether_header *) pkt_data;
	pcap_t *pcaph = (pcap_t *) param;

	if (header->caplen < sizeof(struct ether_header)) return;

	if (eth->ether_type == htons(ETHERTYPE_IP)) {
		handle_ip(pcaph, pkt_data, header->caplen);
	} else if (eth->ether_type == htons(ETHERTYPE_ARP)) {
		handle_arp(pcaph, pkt_data, header->caplen);
	}
}
