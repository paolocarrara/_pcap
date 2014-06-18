#ifndef PCAP_H
#define PCAP_H
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

#define ETHERNET_LINK_TYPE	0

#define MAGIC_1		0xa1b2c3d4
#define MAGIC_2		0xa1b23c4d


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

FILE *fopen_pcap (char *);

/*PCAP GLOBAL HEADER FUNCTIONS*/
uint16_t fread_pcap_file_header		(FILE *, struct pcap_file_header *);
uint16_t fwrite_pcap_file_header 	(FILE *, struct pcap_file_header);

/*PCAP PACKET HEADER FUNCTIONS*/
uint16_t fread_pcap_packet_header 	(FILE *, struct pcap_packet_header *);
uint16_t fwrite_pcap_packet_header 	(FILE *, struct pcap_packet_header); /*funcao nao implementada*/

#endif
