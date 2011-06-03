/*
 * spi: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#ifndef _DATASTRUCTURES_H_
#define _DATASTRUCTURES_H_

#include <stdint.h>
#include <sys/time.h>
#include <libpjf/lib.h>
#include <pcap.h>

struct spi;

/** Label identifying a protocol */
typedef uint8_t spi_label_t;

/** Max value of spi_label_t */
#define SPI_LABEL_MAX 255

/** Table with classification probabilities */
typedef double spi_cprob_t[SPI_LABEL_MAX + 1];

/** Endpoint address (ip << 32 | port) */
typedef uint64_t spi_epaddr_t;

/** Protocol type */
typedef enum {
	SPI_PROTO_TCP = 1,
	SPI_PROTO_UDP
} spi_proto_t;

/** spi traffic source type */
typedef enum {
	SPI_SOURCE_FILE = 1,
	SPI_SOURCE_SNIFF
} spi_source_t;

/** spi event handler
 * @param spi               spi root
 * @param evname            spi event name
 * @param arg               event opaque data
 * @retval false            unsubscribe the handler from spi event
 */
typedef bool spi_event_cb_t(struct spi *spi, const char *evname, void *arg);

/************************************************************************/

/** Traffic source */
struct spi_source {
	struct spi *spi;                    /** root node */
	spi_source_t type;                  /** source type */
	spi_label_t label;                  /** associated source label (for learning) */

	int fd;                             /** underlying fd to monitor for read() possibility */
	struct event *evread;               /** fd read event */
	unsigned int counter;               /** packet counter */
	unsigned int samples;               /** number of samples found */
	unsigned int learned;               /** samples used for learning */
	unsigned int eps;                   /** number of endpoints */

	/** internal data depending on type */
	union {
		struct spi_source_file_t {
			pcap_t *pcap;               /** libpcap handler */
			const char *path;           /** file path */
			struct timeval time;        /** virtual current time in file (time of last packet or inf.) */
			struct timeval gctime;      /** virtual time of last garbage collector call */
		} file;

		struct spi_source_sniff_t {
			pcap_t *pcap;               /** libpcap handler */
			const char *ifname;         /** interface name */
		} sniff;
	} as;
};

/** Represents information extracted from single packet */
struct spi_pkt {
	uint8_t *payload;                   /** payload */
	struct timeval ts;                  /** time of packet (NB: may be from pcap file) */
	uint16_t size;                      /** packet size */
};

/** Represents a single endpoint */
struct spi_ep {
	mmatic *mm;                         /** mm for this endpoint */
	struct spi_source *source;          /** source that created this endpoint */
	spi_proto_t proto;                  /** protocol */
	spi_epaddr_t epa;                   /** endpoint address */

	struct timeval last;                /** time of last packet (for GC) */
	tlist *pkts;                        /** collected packets */
	bool pending;                       /** true if tlist_count(pkts) >= C */

	spi_label_t verdict;                /** current verdict */
	double verdict_prob;                /** current verdict probability */
	uint32_t verdict_count;             /** number of verdicts so far */

	void *vdata;                        /** classifier verdict internal data */
};

/** Represents classification result */
struct spi_classresult {
	struct spi_ep *ep;                      /** endpoint */
	spi_label_t result;                     /** most probable result */
	spi_cprob_t cprob;                      /** classification probabilities */
};

/** Represents a flow */
struct spi_flow {
	struct timeval last;                /** time of last packet (for GC) */

	struct spi_source *source;          /** source that created this flow */
	spi_proto_t proto;                  /** flow protocol */
	spi_epaddr_t epa1;                  /** lower epaddr */
	spi_epaddr_t epa2;                  /** greater epaddr */

	uint32_t counter;                   /** packet counter */
	uint8_t rst;                        /** RST counter */
	uint8_t fin;                        /** FIN counter */
};

/** spi configuration options */
struct spi_options {
	uint8_t N;                          /** payload bytes */
	uint8_t P;                          /** packets per TCP flow */
	uint8_t C;                          /** packets per endpoint window */
};

/** Main data root */
struct spi {
	mmatic *mm;                         /** global mm */
	struct spi_options options;         /** spi options */
	bool running;                       /** true if in spi_loop() */

	struct event_base *eb;              /** libevent root */
	struct event *evgc;                 /** garbage collector event */

	thash *subscribers;                 /** subscribers of spi events: thash of tlists of struct spi_subscriber */
	thash *aggstatus;                   /** thash of int aggregation status: see SPI_AGG_* */
#define SPI_AGG_IGNORE  0
#define SPI_AGG_READY   1
#define SPI_AGG_PENDING 2

	tlist *sources;                     /** traffic sources: list of struct spi_source */
	thash *eps;                         /** endpoints: struct spi_ep indexed by file_fd-proto-epa */
	thash *flows;                       /** flows: struct spi_flow indexed by file_fd-proto-epa1-epa2 where epa1 < epa2 */

	void *cdata;                        /** classifiers private data */
	void *vdata;                        /** verdict private data */
};

/** spi event representation */
struct spi_event {
	struct spi *spi;                    /** spi root */
	const char *evname;                 /** event name */
	tlist *sl;                          /** subscriber list */
	void *arg;                          /** opaque data */
	bool argfree;                       /** free arg after handler call */
};

struct spi_subscriber {
	spi_event_cb_t *handler;           /** handler address */
};

#endif
