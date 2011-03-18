/*
 * pcap2matlab - very simple pcap capture file to Matlab converter
 * Author: Paweł Foremski <pawel@foremski.pl> 2011
 *
 * Heavily based on pcap2c:
 * Written by Vanya A. Sergeev - vsergeev@gmail.com - www.frozeneskimo.com
 * Version 1.0 - June 19th, 2007
 *
 * The source code stinks, feel free to complain and fix.
 *
 * TODO?
 * - support for emitting MAT files
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
//#include "mex.h"

/**
 * From the Wireshark Wiki, the Libpcap file format is defined as:
 * |Global Header|Packet Header|Packet Data|Packet Header|Packet Data| ...
 * Global header is:
 *	- 32-bit magic number
 *	- 16-bit version major number
 *	- 16-bit version minor number
 *	- 32-bit correction time between GMT and other timezone in seconds
 *	- 32-bit significant figures, accuracy of the timestamps
 *	- 32-bit maximum packet length
 *	- 32-bit data link layer type
 *
 * Packet Header is:
 * 	- 32-bit timestamp seconds
 * 	- 32-bit timestamp microseconds
 * 	- 32-bit number of octets of the packet recorded to the file
 * 	- 32-bit actual length of the packet in octets
 *
 * If the magic number is 0xA1B2C3D4, the fields are in the native, unswapped
 * byte order. If the magic number is 0xD4C3B2A1, the fields are in the swapped
 * byte order.
 */

#define PCAP_UNSWAPPED_MAGIC_BYTE   0xA1
#define PCAP_SWAPPED_MAGIC_BYTE     0xD4
#define PCAP_GHEADER_LEN            24
#define PCAP_PHEADER_LEN            16
#define PCAP_ETHERTYPE_OFFSET       12
#define PCAP_IPV4_TYPE              0x0800
#define PCAP_TCP_TYPE               0x06
#define PCAP_UDP_TYPE               0x11

/** payload length */
#define N        12

FILE *pcap_fp;                  /** pcap source */
unsigned int pcap_len;          /** length of pcap_fp in bytes */
bool swapped = false;           /** are pcap header field bytes swapped? */

#define CHECKERR() \
	if (ferror(pcap_fp) != 0) { \
		perror("fgetc"); \
		fprintf(stderr, "Error reading pcap file\n"); \
		fprintf(stderr, "cline=%d, file pos=%ld, pcap_len=%u\n", \
			__LINE__, ftell(pcap_fp), pcap_len); \
		return 1; \
	} else if (ftell(pcap_fp) > pcap_len) { \
		exit(0); \
	}

#define READ4_SWAP(target) do {            \
	if (swapped) {                         \
		target  = fgetc(pcap_fp);          \
		target |= (fgetc(pcap_fp) << 8);   \
		target |= (fgetc(pcap_fp) << 16);  \
		target |= (fgetc(pcap_fp) << 24);  \
	} else {                               \
		target  = (fgetc(pcap_fp) << 24);  \
		target |= (fgetc(pcap_fp) << 16);  \
		target |= (fgetc(pcap_fp) << 8);   \
		target |= fgetc(pcap_fp);          \
	}                                      \
	CHECKERR();                            \
} while(0);

#define READ4(target) do {             \
	target  = (fgetc(pcap_fp) << 24);  \
	target |= (fgetc(pcap_fp) << 16);  \
	target |= (fgetc(pcap_fp) << 8);   \
	target |= fgetc(pcap_fp);          \
	CHECKERR();                        \
} while(0);

#define READ2(target) do {             \
	target  = (fgetc(pcap_fp) << 8);   \
	target |= fgetc(pcap_fp);          \
	CHECKERR();                        \
} while(0);

#define READ(target) do {             \
	target = fgetc(pcap_fp);          \
	CHECKERR();                       \
} while(0);

int main(int argc, char *argv[])
{
	//MATFile *mat_fp;
	uint64_t pkt_id = 1;              /** packet index */
	uint64_t pkt_real_id = 0;         /** packet index in pcap file */

	uint32_t pkt_time;                /** packet timestamp [s] */
	uint32_t pkt_time_us;             /** packet timestamp [us] */
	uint32_t pkt_size;                /** size of the next packet in bytes */
	uint32_t pkt_real_size;           /** real size on the wire */
	uint16_t pkt_type;                /** packet ethertype */

	uint8_t  ip_verlength;            /** IP version and header length [4B] */
	uint16_t ip_proto;                /** IP protocol */
	uint32_t ip_src;                  /** IP source address */
	uint32_t ip_dst;                  /** IP destination address */

	uint16_t p_src;                   /** source port of transport protocol */
	uint16_t p_dst;                   /** destination port */

	uint32_t tcp_seq;                 /** TCP sequence field (or pkt_id if UDP) */
	uint8_t  tcp_offresv;             /** TCP offset / reserved */

	int cur_pos;                      /** current main loop position */
	int next_pos;                     /** position of next packet */
	int payload_pos;                  /** payload position */

	uint32_t time_base = 0;           /** time of first packet */
	int c, i;

	if (argc < 2) {
		fprintf(stderr, "pcap2mat, v. 0.1\n");
		fprintf(stderr, "Paweł Foremski <pawel@foremski.pl> 2011\n");
		fprintf(stderr, "Original pcap2c by Vanya A. Sergeev - vsergeev@gmail.com\n\n");
//		fprintf(stderr, "Usage: %s <libpcap capture file> <MAT output file>\n", argv[0]);
		fprintf(stderr, "Usage: %s <libpcap capture file>\n", argv[0]);
		return 1;
	}

	/* Open the pcap capture file */
	pcap_fp = fopen(argv[1], "r");
	if (pcap_fp == NULL) {
		perror("fopen");
		fprintf(stderr, "Error opening pcap capture file!\n");
		return 1;
	}

	/* Open the MAT file */
	/*mat_fp = matOpen(argv[2], "w");
	if (mat_fp == NULL) {
		perror("fopen");
		fprintf(stderr, "Error opening MAT output file!\n");
		return 1;
	}*/

	/* Seek to the end of the file so we can determine the length */
	if (fseek(pcap_fp, 0, SEEK_END) != 0) {
		perror("fseek");
		fprintf(stderr, "Error determining length of file!\n");
		return 1;
	}

	/* Get the offset of this position (aka length of file) */
	pcap_len = ftell(pcap_fp);
	if (pcap_len == -1L) {
		perror("ftell");
		fprintf(stderr, "Error determining length of file!\n");
		return 1;
	}
	rewind(pcap_fp);

	/* Read the first byte of the 32-bit magic number and determine if the
 	 * fields are swapped by it. */
	READ(c);
	if (c == PCAP_SWAPPED_MAGIC_BYTE) {
		swapped = true;
	} else if (c == PCAP_UNSWAPPED_MAGIC_BYTE) {
		swapped = false;
	} else {
		fprintf(stderr, "Could not detect valid magic number!\n");
		return 1;
	}

	printf("%% dump of %s, N=%d\n\n", argv[1], N);
	printf("pkt = struct;\n");

	/* read packets in loop */
	next_pos = PCAP_GHEADER_LEN;
	while (fseek(pcap_fp, next_pos, SEEK_SET) == 0) {
		pkt_real_id++;

		READ4_SWAP(pkt_time);
		READ4_SWAP(pkt_time_us);
		READ4_SWAP(pkt_size);
		READ4_SWAP(pkt_real_size);

		cur_pos = next_pos;
		next_pos += PCAP_PHEADER_LEN + pkt_size;

		if (time_base == 0)
			time_base = pkt_time;
		pkt_time -= time_base;

		/* check if IPv4 */
		fseek(pcap_fp, PCAP_ETHERTYPE_OFFSET, SEEK_CUR);
		READ2(pkt_type);
		if (pkt_type != PCAP_IPV4_TYPE) {
			printf("%% skipping %llu: not IPv4\n", pkt_real_id);
			continue;
		}

		payload_pos = ftell(pcap_fp);             /* NB: position on IP payload */

		/* get TCP/UDP header location */
		READ(ip_verlength);
		payload_pos += (ip_verlength & 0x0f) * 4; /* NB: position on TCP/UDP header */

		/* check if TCP/UDP */
		fseek(pcap_fp, 8, SEEK_CUR);
		READ(ip_proto);
		if (ip_proto != PCAP_TCP_TYPE && ip_proto != PCAP_UDP_TYPE) {
			printf("%% skipping %llu: not TCP nor UDP\n", pkt_real_id);
			continue;
		}

		/* get src/dst IP */
		fseek(pcap_fp, 2, SEEK_CUR);
		READ4(ip_src);
		READ4(ip_dst);

		/* parse TCP/UDP header */
		fseek(pcap_fp, payload_pos, SEEK_SET);
		if (ip_proto == PCAP_TCP_TYPE) {
			READ2(p_src);
			READ2(p_dst);
			READ4(tcp_seq);
			fseek(pcap_fp, 4, SEEK_CUR);

			READ(tcp_offresv);
			payload_pos += (tcp_offresv >> 4) * 4; /* NB: position on TCP payload */
		} else { /* UDP */
			READ2(p_src);
			READ2(p_dst);

			payload_pos += 8;                      /* NB: position on UDP payload */
		}

		/* check payload length >= N */
		if (next_pos - payload_pos < N) {
			printf("%% skipping %llu: not enough bytes (%d vs %d)\n",
				pkt_real_id, next_pos - payload_pos, N);
			continue;
		}

		/* subtract headers from payload length */
		pkt_real_size -= payload_pos - (cur_pos + PCAP_PHEADER_LEN);

		/* start the packet unsigned char array */
		printf("pkt(%llu).id = %llu;\n", pkt_id, pkt_id);
		printf("pkt(%llu).real_id = %llu;\n", pkt_id, pkt_real_id);
		printf("pkt(%llu).time = %u;\n", pkt_id, pkt_time);
		printf("pkt(%llu).time_us = %u;\n", pkt_id, pkt_time_us);
		printf("pkt(%llu).size = %u;\n", pkt_id, pkt_real_size);
		printf("pkt(%llu).srcip = %u;\n", pkt_id, ip_src);
		printf("pkt(%llu).dstip = %u;\n", pkt_id, ip_dst);
		printf("pkt(%llu).srcport = %u;\n", pkt_id, p_src);
		printf("pkt(%llu).dstport = %u;\n", pkt_id, p_dst);
		printf("pkt(%llu).tcp = %d;\n", pkt_id, (ip_proto == PCAP_TCP_TYPE));
		printf("pkt(%llu).tcpseq = %u;\n", pkt_id, (ip_proto == PCAP_TCP_TYPE) ? tcp_seq : 0);
		printf("pkt(%llu).payload = [ ", pkt_id);

		fseek(pcap_fp, payload_pos, SEEK_SET);
		for (i = 0; i < N; i++) {
			READ(c);
			printf("%d %d ", c, c & 0x0f, c >> 4);
		}
		printf("];\n\n");

		/* Increment the packet index */
		pkt_id++;

		if (next_pos >= pcap_len)
			break;
	}

	return 0;
}
