#include "_pcap.h"
#include <time.h>
#include <stdlib.h>

struct pcap_file_header fread_pcap_file_header (FILE *fp) {

	printf("entrei aqui\n");

	struct pcap_file_header file_hdr;
	if ( fread_magic (fp, &file_hdr.magic) != 0) {
		printf ("Error: coudn't read the magic number.\n");
	}
	if ( fread_major (fp, &file_hdr.major) != 0) {
		printf ("Error: coudn't read the major version number.\n");
	}
	if ( fread_minor (fp, &file_hdr.minor) != 0){
		printf ("Error: coudn't read the major version number.\n");
	}
	fread_zone 	(fp, &file_hdr.thiszone);
	fread_sigfigs 	(fp, &file_hdr.sigfigs);
	fread_snaplen 	(fp, &file_hdr.snaplen);
	fread_linktype 	(fp, &file_hdr.linktype);
	
	return file_hdr;
}
unsigned int fread_magic (FILE *fp, unsigned int *magic) {
	fseek(fp, LOC_MAGIC, SEEK_SET);
	if ( fread (magic, sizeof (unsigned int), 1, fp) != 1) {
		return 2;
	}
	return 0;
}
unsigned int fread_major (FILE *fp, unsigned short int *major) {
	fseek(fp, LOC_MAJOR, SEEK_SET);
	if ( fread (major, sizeof(unsigned short int), 1, fp) != 1) {
		return 4;
	}
	return 0;
}
unsigned int fread_minor (FILE *fp, unsigned short int *minor) {
	fseek(fp, LOC_MINOR, SEEK_SET);
	if ( fread (minor, sizeof(unsigned short int), 1, fp) != 1) {
		return 8;
	}
	return 0;
}
unsigned int fread_zone (FILE *fp, int *zone) {
	fseek(fp, LOC_ZONE, SEEK_SET);
	if ( fread (zone, sizeof(int), 1, fp) != 1) {
		return 16;
	}
	return 0;
}
unsigned int fread_sigfigs (FILE *fp, unsigned int *sigfigs) {
	fseek(fp, LOC_SIGFIGS, SEEK_SET);
	if ( fread (sigfigs, sizeof (unsigned int), 1, fp) != 1) {
		return 32;
	}
	return 0;
}
unsigned int fread_snaplen (FILE *fp, unsigned int *snaplen) {
	fseek(fp, LOC_SNAPLEN, SEEK_SET);
	if ( fread (snaplen, sizeof (unsigned int), 1, fp) != 1) {
		return 64;
	}
	return 0;
}
unsigned int fread_linktype (FILE *fp, unsigned int *linktype) {
	fseek(fp, LOC_LINKTYPE, SEEK_SET);
	if ( fread (linktype, sizeof (unsigned int), 1, fp) != 1) {
		return 128;
	}
	return 0;
}
unsigned int set_magic (struct pcap_file_header *file_hdr, unsigned int magic) {
	file_hdr->magic = magic;
	return 0;
}
unsigned int set_major (struct pcap_file_header *file_hdr, unsigned short int major) {
	file_hdr->major = major;
	return 0;
}
unsigned int set_minor (struct pcap_file_header *file_hdr, unsigned short int minor) {
	file_hdr->minor = minor;
	return 0;
}
unsigned int set_zone (struct pcap_file_header *file_hdr, int zone) {
	file_hdr->thiszone = zone;
	return 0;
}
unsigned int set_sigfigs (struct pcap_file_header *file_hdr, unsigned int sigfigs) {
	file_hdr->sigfigs = sigfigs;
	return 0;
}
unsigned int set_snaplen (struct pcap_file_header *file_hdr, unsigned int snaplen) {
	file_hdr->snaplen = snaplen;
	return 0;
}
unsigned int set_linktype (struct pcap_file_header *file_hdr, unsigned int linktype) {
	file_hdr->linktype = linktype;
	return 0;
}

unsigned int fwrite_magic (FILE *fp, unsigned int magic) {
	fseek (fp, LOC_MAGIC, SEEK_SET);
	if ( fwrite (&magic, sizeof (unsigned int), 1, fp) != 1) {
		return 8;
	}
	return 0;
}
unsigned int fwrite_major (FILE *fp, unsigned short int major) {
	fseek (fp, LOC_MAJOR, SEEK_SET);
	if ( fwrite (&major, sizeof (unsigned short int), 1, fp) != 1) {
		return 9;
	}
	return 0;
}
unsigned int fwrite_minor (FILE *fp, unsigned short int minor) {
	fseek (fp, LOC_MINOR, SEEK_SET);
	if ( fwrite (&minor, sizeof (unsigned short int), 1, fp) != 1 ) {
		return 10;
	}
	return 0;
}
unsigned int fwrite_zone (FILE *fp, int zone) {
	fseek (fp, LOC_ZONE, SEEK_SET);
	if ( fwrite (&zone, sizeof (int), 1, fp) != 1 ) {
		return 11;
	}
	return 0;
}
unsigned int fwrite_sigfigs (FILE *fp, unsigned int sigfigs) {
	fseek (fp, LOC_SIGFIGS, SEEK_SET);
	if ( fwrite (&sigfigs, sizeof (unsigned int), 1, fp) != 1 ) {
		return 12;
	}
	return 0;
}
unsigned int fwrite_snaplen (FILE *fp, unsigned int snaplen) {
	fseek (fp, LOC_SNAPLEN, SEEK_SET);
	if ( fwrite (&snaplen, sizeof (unsigned int), 1, fp) != 1 ) {
		return 13;
	}
	return 0;
}
unsigned int fwrite_linktype (FILE *fp, unsigned int linktype) {
	fseek (fp, LOC_LINKTYPE, SEEK_SET);
	if ( fwrite (&linktype, sizeof (unsigned int), 1, fp) != 1 ) {
		return 14;
	}
	return 0;
}

void write_pcap_file_header (struct pcap_file_header file_hdr) {
	printf ("magic: \t\t%x\n", file_hdr.magic);
	printf ("major: \t\t%x\n", file_hdr.major);
	printf ("minor: \t\t%x\n", file_hdr.minor);
	printf ("zone: \t\t%x\n", file_hdr.thiszone);
	printf ("sigfigs: \t%x\n", file_hdr.sigfigs);
	printf ("snaplen: \t%x\n", file_hdr.snaplen);
	printf ("linktype: \t%x\n", file_hdr.linktype);
}
unsigned int fwrite_pcap_file_header (FILE *fp, struct pcap_file_header file_hdr) {
	fwrite_magic 	(fp, file_hdr.magic);
	fwrite_major 	(fp, file_hdr.major);
	fwrite_minor 	(fp, file_hdr.minor);
	fwrite_zone 	(fp, file_hdr.thiszone);
	fwrite_sigfigs 	(fp, file_hdr.sigfigs);
	fwrite_snaplen 	(fp, file_hdr.snaplen);
	fwrite_linktype	(fp, file_hdr.linktype);
	return 0;
}

struct pcap_file_header get_pcap_file_header () {
	struct pcap_file_header file_hdr;
	set_magic 	(&file_hdr, MAGIC_LITTLE);
	set_major 	(&file_hdr, MAJOR);
	set_minor 	(&file_hdr, MINOR);
	set_zone 	(&file_hdr, 0);
	set_sigfigs 	(&file_hdr, 0);
	set_snaplen 	(&file_hdr, SNAPLEN);
	set_linktype 	(&file_hdr, 0);
	return file_hdr;
}



unsigned int fread_pcap_packet_header (FILE *fp, struct pcap_packet_header *pckt_hdr) {
	unsigned int status = 0;

	status += fread_tv_sec (fp, &pckt_hdr->tv_sec);
	status += fread_tv_usec (fp, &pckt_hdr->tv_usec);
	status += fread_caplen (fp, &pckt_hdr->caplen);
	status += fread_len (fp, &pckt_hdr->len);

	return status;
}
unsigned int fread_tv_sec (FILE *fp, unsigned int *tv_sec) {
	if ( fread (tv_sec, sizeof (unsigned int), 1, fp) != 1 ) {
		return 16;
	}
	return 0;
}
unsigned int fread_tv_usec (FILE *fp, unsigned int *tv_usec) {
	if ( fread (tv_usec, sizeof (unsigned int), 1, fp) != 1 ) {
		return 17;
	}
	return 0;
}
unsigned int fread_caplen (FILE *fp, unsigned int *caplen) {
	if ( fread (caplen, sizeof (unsigned int), 1, fp) != 1 ) {
		return 18;
	}
	return 0;
}
unsigned int fread_len (FILE *fp, unsigned int *len) {
	if ( fread (len, sizeof (unsigned int), 1, fp) != 1 ) {
		return 19;
	}
	return 0;
}
unsigned int set_tv_sec (struct pcap_packet_header *pckt_hdr, unsigned int tv_sec) {
	pckt_hdr->tv_sec = tv_sec;
	return 0;
}
unsigned int set_tv_usec (struct pcap_packet_header *pckt_hdr, unsigned int tv_usec) {
	pckt_hdr->tv_usec = tv_usec;
	return 0;
}
unsigned int set_tv_caplen (struct pcap_packet_header *pckt_hdr, unsigned int caplen) {
	pckt_hdr->caplen = caplen;
	return 0;
}
unsigned int set_tv_len (struct pcap_packet_header *pckt_hdr, unsigned int len) {
	pckt_hdr->len = len;
	return 0;
}
void write_pcap_packet_header(struct pcap_packet_header pckt_hdr) {
	printf("tv_sec: \t%x \t%d\n", pckt_hdr.tv_sec, pckt_hdr.tv_sec);
	printf("tv_usec: \t%x \t\t%d\n", pckt_hdr.tv_usec, pckt_hdr.tv_usec);
	printf("caplen: \t%x \t\t%d\n", pckt_hdr.caplen, pckt_hdr.caplen);
	printf("len: \t\t%x \t\t%d\n", pckt_hdr.len, pckt_hdr.len);
}


void fread_packet (FILE *fp, struct pcap_packet_header pckt_hdr) {
	//fseek (fp, pckt_hdr.caplen, SEEK_CUR);
	
	int i;

	int IPV4_PROTOCOL = 8;
	int IPV6_PROTOCOL = 34525;
	int ARP_PROTOCOL = 2054;

	int ETHERNET_LENGTH = 14;
	int ARP_LENGTH = 28;
	int IPV4_LENGTH = 20;
	int IPV6_LENGTH = 20;	

	unsigned char *dest = malloc(6*sizeof(char));
	unsigned char *orig = malloc(6*sizeof(char));
	unsigned short int h_proto;

	unsigned short int first_16_bits;
	unsigned short int second_16_bits;
	unsigned short int third_16_bits;
	unsigned short int fourth_16_bits;
	unsigned short int ttl;
	unsigned short int protocol;
	unsigned short int sixth_16_bits;
	unsigned int src_address;
	unsigned int dst_address;

	fread (dest, 6*sizeof(char), 1, fp);
	fread (orig, 6*sizeof(char), 1, fp);
	fread (&h_proto, sizeof(unsigned short int), 1, fp);

	fread (&first_16_bits, sizeof (unsigned short int), 1, fp);
	fread (&second_16_bits, sizeof (unsigned short int), 1, fp);
	fread (&third_16_bits, sizeof (unsigned short int), 1, fp);
	fread (&fourth_16_bits, sizeof (unsigned short int), 1, fp);
	fread (&ttl, sizeof (char), 1, fp);
	fread (&protocol, sizeof (char), 1, fp);
	fread (&sixth_16_bits, sizeof (unsigned short int), 1, fp);
	fread (&src_address, sizeof (unsigned int), 1, fp);
	fread (&dst_address, sizeof (unsigned int), 1, fp);
	
	printf("Ethernet protocol\n");
	printf("Origin: ");
	for (i = 0; i < 6; i++)
		printf("%02x ", orig[i]);
	printf("\n");
	printf("Destin: ");
	for (i = 0; i < 6; i++)
		printf("%02x ", dest[i]);
	printf("\n");
	printf("Protocol: %x\n", h_proto);
	
	putchar('\n');

	printf ("IPV4 protocol\n");
	printf ("Total Length: %u\n", second_16_bits);
	printf ("Identifcantion : %u\n", third_16_bits);
	printf ("Checksum : %u\n", sixth_16_bits);
	printf ("IP Origin: %u\n", src_address);
	printf ("IP Destin: %u\n", dst_address);
	printf ("Time to live: %u\n", ttl);
	printf ("Next protocol: %u\n", protocol);

	fseek (fp, pckt_hdr.caplen - 14 - 20, SEEK_CUR);

	
	putchar('\n');
	
}
