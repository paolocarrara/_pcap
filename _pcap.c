#include "_pcap.h"
#include <stdlib.h>

/*GLOBAL HEADER FUNCTIONS*/
static inline uint16_t fread_magic	(FILE *, uint32_t *);
static inline uint16_t fread_major	(FILE *, uint16_t *);
static inline uint16_t fread_minor	(FILE *, uint16_t *);
static inline uint16_t fread_zone 	(FILE *, int32_t  *);
static inline uint16_t fread_sigfigs 	(FILE *, uint32_t *);
static inline uint16_t fread_snaplen 	(FILE *, uint32_t *);
static inline uint16_t fread_linktype 	(FILE *, uint32_t *);

uint16_t fread_pcap_file_header (FILE *fp, struct pcap_file_header *pcap_file_hdr) 
{
	rewind (fp);
	return 	fread_magic 	(fp, &pcap_file_hdr->magic) +
		fread_major 	(fp, &pcap_file_hdr->v_major) +
		fread_minor 	(fp, &pcap_file_hdr->v_minor) +
		fread_zone 	(fp, &pcap_file_hdr->thiszone) +
		fread_sigfigs	(fp, &pcap_file_hdr->sigfigs) +
		fread_snaplen	(fp, &pcap_file_hdr->snaplen) +
		fread_linktype	(fp, &pcap_file_hdr->linktype);
}
static inline uint16_t fread_magic (FILE *fp, uint32_t *magic) 
	{ return fread (magic, sizeof (uint32_t), 1, fp); }
static inline uint16_t fread_major (FILE *fp, uint16_t *v_major) 
	{ return fread (v_major, sizeof(uint16_t), 1, fp); }
static inline uint16_t fread_minor (FILE *fp, uint16_t *v_minor) 
	{ return fread (v_minor, sizeof(uint16_t), 1, fp); }
static inline uint16_t fread_zone (FILE *fp, int32_t *zone) 
	{ return fread (zone, sizeof(int32_t), 1, fp); }
static inline uint16_t fread_sigfigs (FILE *fp, uint32_t *sigfigs) 
	{ return fread (sigfigs, sizeof (uint32_t), 1, fp); }
static inline uint16_t fread_snaplen (FILE *fp, uint32_t *snaplen) 
	{ return fread (snaplen, sizeof (uint32_t), 1, fp); }
static inline uint16_t fread_linktype (FILE *fp, uint32_t *linktype) 
	{ return fread (linktype, sizeof (uint32_t), 1, fp); }

static inline uint16_t fwrite_magic 	(FILE *, uint32_t);
static inline uint16_t fwrite_major 	(FILE *, uint16_t);
static inline uint16_t fwrite_minor 	(FILE *, uint16_t);
static inline uint16_t fwrite_zone 	(FILE *, int32_t );
static inline uint16_t fwrite_sigfigs 	(FILE *, uint32_t);
static inline uint16_t fwrite_snaplen 	(FILE *, uint32_t);
static inline uint16_t fwrite_linktype 	(FILE *, uint32_t);

uint16_t fwrite_pcap_file_header (FILE *fp, struct pcap_file_header file_hdr) 
{
	rewind (fp);
	return	fwrite_magic 	(fp, file_hdr.magic) +
		fwrite_major 	(fp, file_hdr.v_major) +
		fwrite_minor 	(fp, file_hdr.v_minor) +
		fwrite_zone 	(fp, file_hdr.thiszone) +
		fwrite_sigfigs 	(fp, file_hdr.sigfigs) +
		fwrite_snaplen 	(fp, file_hdr.snaplen) +
		fwrite_linktype	(fp, file_hdr.linktype);
}
static inline uint16_t fwrite_magic (FILE *fp, uint32_t magic) 
	{ fwrite (&magic, sizeof (uint32_t), 1, fp); }
static inline uint16_t fwrite_major (FILE *fp, uint16_t v_major) 
	{ fwrite (&v_major, sizeof (uint16_t), 1, fp); }
static inline uint16_t fwrite_minor (FILE *fp, uint16_t v_minor) 
	{ fwrite (&v_minor, sizeof (uint16_t), 1, fp); }
static inline uint16_t fwrite_zone (FILE *fp, int32_t zone) 
	{ fwrite (&zone, sizeof (int32_t), 1, fp); }
static inline uint16_t fwrite_sigfigs (FILE *fp, uint32_t sigfigs) 
	{ fwrite (&sigfigs, sizeof (uint32_t), 1, fp); }
static inline uint16_t fwrite_snaplen (FILE *fp, uint32_t snaplen) 
	{ fwrite (&snaplen, sizeof (uint32_t), 1, fp); }
static inline uint16_t fwrite_linktype (FILE *fp, uint32_t linktype) 
	{ fwrite (&linktype, sizeof (uint32_t), 1, fp); }

/*PACKET HEADER FUNCTIONS*/
static inline uint16_t fread_tv_sec 	(FILE *, uint32_t *);
static inline uint16_t fread_tv_usec 	(FILE *, uint32_t *);
static inline uint16_t fread_caplen 	(FILE *, uint32_t *);
static inline uint16_t fread_len 	(FILE *, uint32_t *);

uint16_t fread_pcap_packet_header (FILE *fp, struct pcap_packet_header *pckt_hdr) 
{		
	return 	fread_tv_sec (fp, &pckt_hdr->tv_sec) +
		fread_tv_usec (fp, &pckt_hdr->tv_usec) + 
		fread_caplen (fp, &pckt_hdr->caplen) +
		fread_len (fp, &pckt_hdr->len);
}
static inline uint16_t fread_tv_sec (FILE *fp, uint32_t *tv_sec) 
	{ return fread (tv_sec, sizeof (uint32_t), 1, fp); }
static inline uint16_t fread_tv_usec (FILE *fp, uint32_t *tv_usec) 
	{ return fread (tv_usec, sizeof (uint32_t), 1, fp); }
static inline uint16_t fread_caplen (FILE *fp, uint32_t *caplen) 
	{ return fread (caplen, sizeof (uint32_t), 1, fp); }
static inline uint16_t fread_len (FILE *fp, uint32_t *len) 
	{ return fread (len, sizeof (uint32_t), 1, fp); }
