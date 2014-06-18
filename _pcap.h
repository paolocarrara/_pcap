#ifndef PCAP_H
#define PCAP_H
#include <stdio.h>
#include <time.h>
#include <stdint.h>

#define ETHERNET_LINK_TYPE	0

struct pcap_file_header {
	uint32_t magic;
	uint16_t v_major;
	uint16_t v_minor;
	int32_t thiszone;
	uint32_t sigfigs;
	uint32_t snaplen;
	uint32_t linktype;
};

struct pcap_packet_header {
	uint32_t tv_sec;
	uint32_t tv_usec;
	uint32_t caplen;
	uint32_t len;
};

/*PCAP FILE HEADER PORTION*/
uint16_t fread_pcap_file_header		(FILE *, struct pcap_file_header *);
uint16_t fwrite_pcap_file_header 	(FILE *, struct pcap_file_header);

/*PCAP PACKET HEADER PORTION*/
uint16_t fread_pcap_packet_header 	(FILE *, struct pcap_packet_header *);
uint16_t fwrite_pcap_packet_header 	(FILE *, struct pcap_packet_header); /*funcao nao implementada*/

#endif
