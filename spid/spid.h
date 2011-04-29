/*
 * spid: Statistical Packet Inspection
 *
 * Paweł Foremski <pawel@foremski.pl> 2011
 */

#ifndef _SPID_H_
#define _SPID_H_

#include <stdint.h>
#include <sys/time.h>

/** Number of packets in classification window */
#define C 80

/** Max number of packets from single TCP connection */
#define P 5

/** Number of payload bytes to analyze */
#define N 12

/** protocol type */
enum proto_t {
	SPC_PROTO_TCP = 1,
	SPC_PROTO_UDP
};

/** Traffic source */
struct source {
	/** source type */
	enum type_t {
		SPC_SOURCE_PCAP = 1,
		SPC_SOURCE_SNIFF
	} type;

	/** internal data depending on type */
	union {
		struct pcap_t {
			const char *path;           /** file path */
		} pcap;

		struct sniff_t {
			const char *ifname;         /** interface name */
		} sniff;
	} as;

	/** associated source label (for learning) */
	uint8_t label;
};

/** Represents information extracted from single packet */
struct pkt {
	uint8_t payload[N];                 /** payload */
	struct timeval ts;                  /** timestamp */
	uint16_t size;                      /** packet size */
};

/** Represents a single endpoint */
struct ep {
	enum proto_t proto;                 /** protocol */
	uint32_t ip;                        /** IP address */
	uint16_t port;                      /** port number */
	struct timeval first;               /** time of first packet */
	struct timeval last;                /** time of last packet */
	struct pkt pkt[C];                  /** collected packets */

	uint8_t label;                      /** label for learning (if != 0) */
	uint8_t verdict;                    /** classifier verdict (if != 0) */
};

/** Represents a single flow (eg. a TCP connection) */
struct flow {
	uint32_t counter;                   /** packet counter */
	struct timeval last;                /** time of last packet */
	struct ep *ep1;                     /** one side */
	struct ep *ep2;                     /** second side */
};

#endif
