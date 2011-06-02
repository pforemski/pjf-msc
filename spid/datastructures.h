/*
 * spid: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#ifndef _DATASTRUCTURES_H_
#define _DATASTRUCTURES_H_

#include <stdint.h>
#include <sys/time.h>
#include <libpjf/lib.h>
#include <pcap.h>

struct spid;

/** Label identifying a protocol */
typedef uint8_t label_t;
/* keep in sync */
#define SPI_MAXLABEL 255

/** Table with classification probabilities */
typedef double cprob_t[SPI_MAXLABEL+1];

/** Endpoint address (ip << 32 | port) */
typedef uint64_t epaddr_t;

/** Protocol type */
typedef enum {
	SPI_PROTO_TCP = 1,
	SPI_PROTO_UDP
} proto_t;

/** spid traffic source type */
typedef enum {
	SPI_SOURCE_FILE = 1,
	SPI_SOURCE_SNIFF
} spid_source_t;

/** spid event handler
 * @param spid              spid root
 * @param evname            spid event name
 * @param arg               event opaque data
 */
typedef void spid_event_cb_t(struct spid *spid, const char *evname, void *arg);

/************************************************************************/

/** Traffic source */
struct source {
	struct spid *spid;                  /** root node */
	spid_source_t type;                 /** source type */
	label_t label;                      /** associated source label (for learning) */

	int fd;                             /** underlying fd to monitor for read() possibility */
	struct event *evread;               /** fd read event */
	int counter;                        /** packet counter */

	/** internal data depending on type */
	union {
		struct source_file_t {
			pcap_t *pcap;               /** libpcap handler */
			const char *path;           /** file path */
			struct timeval time;        /** virtual current time in file (time of last packet or inf.) */
			struct timeval gctime;      /** virtual time of last garbage collector call */
		} file;

		struct source_sniff_t {
			pcap_t *pcap;               /** libpcap handler */
			const char *ifname;         /** interface name */
		} sniff;
	} as;
};

/** Represents information extracted from single packet */
struct pkt {
	uint8_t *payload;                   /** payload */
	struct timeval ts;                  /** time of packet (NB: may be from pcap file) */
	uint16_t size;                      /** packet size */
};

/** Represents a single endpoint */
struct ep {
	mmatic *mm;                         /** mm for this endpoint */
	struct source *source;              /** source that created this endpoint */
	proto_t proto;                      /** protocol */
	epaddr_t epa;                       /** endpoint address */

	struct timeval last;                /** time of last packet (for GC) */
	tlist *pkts;                        /** collected packets */
	bool pending;                       /** true if tlist_count(pkts) >= C */

	label_t verdict;                    /** current verdict */
	double verdict_prob;                /** current verdict probability */
	uint32_t verdict_count;             /** number of verdicts so far */

	void *vdata;                        /** classifier verdict internal data */
};

/** Represents classification result */
struct classification_result {
	struct ep *ep;                      /** endpoint */
	label_t result;                     /** most probable result */
	cprob_t cprob;                      /** classification probabilities */
};

/** Represents a flow */
struct flow {
	struct timeval last;                /** time of last packet (for GC) */

	struct source *source;              /** source that created this flow */
	proto_t proto;                      /** flow protocol */
	epaddr_t epa1;                      /** lower epaddr */
	epaddr_t epa2;                      /** greater epaddr */

	uint32_t counter;                   /** packet counter */
	uint8_t rst;                        /** RST counter */
	uint8_t fin;                        /** FIN counter */
};

/** spid configuration options */
struct spid_options {
	uint8_t N;                          /** payload bytes */
	uint8_t P;                          /** packets per TCP flow */
	uint8_t C;                          /** packets per endpoint window */
};

/** Main data root */
struct spid {
	mmatic *mm;                         /** global mm */
	struct spid_options options;        /** spid options */
	bool running;                       /** true if in spid_loop() */

	struct event_base *eb;              /** libevent root */
	struct event *evgc;                 /** garbage collector event */

	thash *subscribers;                 /** subscribers of spid events: thash of tlists of struct spid_subscriber */
	thash *aggstatus;                   /** thash of int aggregation status: see SPI_AGG_* */
#define SPI_AGG_IGNORE  0
#define SPI_AGG_READY   1
#define SPI_AGG_PENDING 2

	tlist *sources;                     /** traffic sources: list of struct source */
	thash *eps;                         /** endpoints: struct ep indexed by file_fd-proto-epa */
	thash *flows;                       /** flows: struct flow indexed by file_fd-proto-epa1-epa2 where epa1 < epa2 */

	void *cdata;                        /** classifiers private data */
	void *vdata;                        /** verdict private data */
};

/** spid event representation */
struct spid_event {
	struct spid *spid;                  /** spid root */
	const char *evname;                 /** event name */
	tlist *sl;                          /** subscriber list */
	void *arg;                          /** opaque data */
	bool argfree;                       /** free arg after handler call */
};

struct spid_subscriber {
	spid_event_cb_t *handler;           /** handler address */
};

#endif
