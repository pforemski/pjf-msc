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

/** Endpoint address (ip << 32 | port) */
typedef uint64_t epaddr_t;

/** Protocol type */
typedef enum {
	SPI_PROTO_TCP = 1,
	SPI_PROTO_UDP
} proto_t;

/** spid event
 * Its a special case of an internal event, distinct from events understood as in libevent */
typedef enum {
	SPI_EVENT_ENDPOINT_HAS_C_PKTS = 1,
	SPI_EVENT_MAX                /* keep it last */
} spid_event_t;

/** spid traffic source type */
typedef enum {
	SPI_SOURCE_FILE = 1,
	SPI_SOURCE_SNIFF
} spid_source_t;

/** spid event handler
 * @param spid              spid root
 * @param code              event code
 * @param data              event opaque data
 */
typedef void spid_event_cb_t(struct spid *spid, spid_event_t code, void *data);

/************************************************************************/

/** Traffic source */
struct source {
	struct spid *spid;                  /** root node */
	spid_source_t type;                 /** source type */
	label_t label;                      /** associated source label (for learning) */

	int fd;                             /** underlying fd to monitor for read() possibility */
	struct event *evread;               /** fd read event */

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
	struct source *source;              /** packet source */
	uint8_t *payload;                   /** payload */
	struct timeval ts;                  /** time of packet (NB: may be from pcap file) */
	uint16_t size;                      /** packet size */
};

/** Verdict information */
struct verdict {
	/** type of verdict decision */
	enum verdict_t {
		SPI_VERDICT_SIMPLE = 1,
		SPI_VERDICT_EWMA
	} type;

	/** internal info */
	union {
		struct verdict_simple_t {
			uint8_t last;
		} simple;

		struct veridct_emwa_t {
			uint16_t ewma_len;          /** EWMA length */
			float verdicts[SPI_MAXLABEL+1]; /** histogram of verdicts over time:
			                                    EWMA(SPI_VERDICTS) of class. probabilty for each label */
		} ewma;
	} as;

	uint32_t count;                     /** number of final decisions so far */
	float prob;                         /** probability of the final decision */
	label_t label;                      /** final decision */
};

/** Represents a single endpoint */
struct ep {
	mmatic *mm;                         /** mm for this endpoint */
	struct source *source;              /** source that created this endpoint */
	proto_t proto;                      /** protocol */
	epaddr_t epa;                       /** endpoint address */

	struct timeval last;                /** time of last packet (for GC) */
	tlist *pkts;                        /** collected packets */
	bool has_C;                         /** true if tlist_count(pkts) >= C */

	struct verdict *verdict;            /** classifier verdict info */
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

	struct event_base *eb;              /** libevent root */
	tlist *subscribers[SPI_EVENT_MAX+1];/** subscribers of spid events: list of struct spid_subscriber */

	struct event *evgc;                 /** garbage collector event */
	bool gcflag;                        /** set to false on each gc run */

	tlist *sources;                     /** traffic sources: list of struct source */
	thash *eps;                         /** endpoints: struct ep indexed by file_fd-proto-ip:port */
	thash *flows;                       /** flows: struct flow indexed by file_fd-proto-ip1:port1-ip2:port2 where ip1 < ip2 */
};

/** spid event representation */
struct spid_event {
	struct spid *spid;                  /** spid root */
	spid_event_t code;                  /** event code */
	void *data;                         /** opaque data */
};

/** spid event subscriber */
struct spid_subscriber {
	spid_event_cb_t *handler;           /** callback to call */
};

#endif
