#include <stdio.h>
#include <time.h>

#define MAGIC_LITTLE 	2712847316
#define MAGIC_BIG 	3285492146
#define MAJOR 		2
#define MINOR 		4
#define SNAPLEN 	65535

#define LOC_MAGIC 	0
#define LOC_MAJOR 	4
#define LOC_MINOR 	6
#define LOC_ZONE 	8
#define LOC_SIGFIGS 	12
#define LOC_SNAPLEN 	16
#define LOC_LINKTYPE 	20

int total;

struct pcap_file_header {
	unsigned int magic;
	unsigned short int major;
	unsigned short int minor;
	int thiszone;
	unsigned int sigfigs;
	unsigned int snaplen;
	unsigned int linktype;
};

struct pcap_packet_header {
	unsigned int tv_sec;
	unsigned int tv_usec;
	unsigned int caplen;
	unsigned int len;
};

/*PCAP FILE HEADER PORTION*/
struct pcap_file_header fread_pcap_file_header (FILE *);
unsigned int fread_magic (FILE *, unsigned int *);
unsigned int fread_major (FILE *, unsigned short int *);
unsigned int fread_minor (FILE *, unsigned short int *);
unsigned int fread_zone (FILE *, int *);
unsigned int fread_sigfigs (FILE *, unsigned int *);
unsigned int fread_snaplen (FILE *, unsigned int *);
unsigned int fread_linktype (FILE *, unsigned int *);

unsigned int set_magic (struct pcap_file_header *, unsigned int);
unsigned int set_major (struct pcap_file_header *, unsigned short int);
unsigned int set_minor (struct pcap_file_header *, unsigned short int);
unsigned int set_zone (struct pcap_file_header *, int);
unsigned int set_sigfigs (struct pcap_file_header *, unsigned int);
unsigned int set_snaplen (struct pcap_file_header *, unsigned int);
unsigned int set_linktype (struct pcap_file_header *, unsigned int);

unsigned int fwrite_magic (FILE *fp, unsigned int);
unsigned int fwrite_major (FILE *fp, unsigned short int);
unsigned int fwrite_minor (FILE *fp, unsigned short int);
unsigned int fwrite_zone (FILE *fp, int);
unsigned int fwrite_sigfigs (FILE *fp, unsigned int);
unsigned int fwrite_snaplen (FILE *fp, unsigned int);
unsigned int fwrite_linktype (FILE *fp, unsigned int);

struct pcap_file_header get_pcap_file_header ();
void write_pcap_file_header (struct pcap_file_header);
unsigned int fwrite_pcap_file_header (FILE *, struct pcap_file_header);

/*PCAP PACKET HEADER PORTION*/
unsigned int fread_pcap_packet_header (FILE *, struct pcap_packet_header *);
/*unsigned int fread_timeval (FILE *, struct timeval *);*/
unsigned int fread_tv_sec (FILE *, unsigned int *);
unsigned int fread_tv_usec (FILE *, unsigned int *);
unsigned int fread_caplen (FILE *, unsigned int *);
unsigned int fread_len (FILE *, unsigned int *);

unsigned int set_tv_sec (struct pcap_packet_header *, unsigned int);
unsigned int set_tv_usec (struct pcap_packet_header *, unsigned int);
unsigned int set_tv_caplen (struct pcap_packet_header *, unsigned int);
unsigned int set_tv_len (struct pcap_packet_header *, unsigned int);

void write_pcap_packet_header (struct pcap_packet_header);
unsigned int fwrite_pcap_packet_header (FILE *fp, struct pcap_packet_header);

void fread_packet (FILE *, struct pcap_packet_header);
