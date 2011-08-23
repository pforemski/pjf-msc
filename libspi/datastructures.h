/*
 * spi: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

/** @file */

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

/** Endpoint address (proto << 48 | ip << 16 | port) */
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
	bool testing;                       /** this source is for performance testing */

	int fd;                             /** underlying fd to monitor for read() possibility */
	struct event *evread;               /** fd read event */
	unsigned int counter;               /** packet counter */
	unsigned int signatures;            /** number of extracted signatures */
	unsigned int learned;               /** samples used for learning */
	unsigned int eps;                   /** number of endpoints */

	bool closed;                        /** true if source is finished */

	/** internal data depending on type */
	union {
		struct {
			pcap_t *pcap;               /** libpcap handler */
			const char *path;           /** file path */
			struct timeval time;        /** virtual current time in file (time of last packet or inf.) */
			struct timeval gctime;      /** virtual time of last garbage collector call */
		} file;

		struct {
			pcap_t *pcap;               /** libpcap handler */
			const char *ifname;         /** interface name */
		} sniff;
	} as;
};

/** Represents window signature (C packets) */
struct spi_signature {
	spi_label_t label;
	struct spi_coordinate {
		int index;
		double value;
	} *c;
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
	spi_epaddr_t epa;                   /** endpoint address */

	struct timeval last;                /** time of last packet (for GC) */
	tlist *pkts;                        /** collected packets */
	bool gclock;                        /** true if endpoint must not be wiped out by GC */

	spi_label_t verdict;                /** current verdict */
	double verdict_prob;                /** current verdict probability */
	uint32_t verdict_count;             /** number of verdicts so far */
	uint32_t predictions;               /** number of predictions made */

	void *vdata;                        /** classifier verdict internal data */
};

/** Represents classification result */
struct spi_classresult {
	struct spi_ep *ep;                      /** endpoint */
	spi_label_t result;                     /** most probable result */
	spi_cprob_t cprob;                      /** classification probabilities */
	spi_cprob_t cprob_lib;                  /** classification probabilities from underlying library */
};

/** Represents a flow */
struct spi_flow {
	struct timeval last;                /** time of last packet (for GC) */

	struct spi_source *source;          /** source that created this flow */
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

	/* KISS */
	bool kiss_std;                      /** use KISS extensions */
	bool kiss_linear;                   /** use liblinear instead of libsvm */
	struct parameter *liblinear_params; /** liblinear params */
	struct svm_parameter *libsvm_params;/** libsvm params */

	/* verdict */
	double verdict_threshold;           /** verdict threshold */
	bool verdict_simple;                /** use simple verdict issuer */
	bool verdict_best;                  /** use 'best' verdict issuer */
	int  verdict_ewma_len;              /** length of EWMA verdict issuer history */
};

/** Performance data */
struct spi_stats {
	uint32_t learned_pkt;                /** number of signatures learned from packet sources */
	uint32_t learned_tq;                 /** number of signatures learned from training queues */

	uint32_t test_all;                   /** total number of endpoints which provided a "test verdict" */
	uint32_t test_is[SPI_LABEL_MAX + 1]; /** ...and number of such endpoints for each label */

	uint32_t test_ok;                    /** total number of valid "test verdicts" */
	uint32_t test_FN[SPI_LABEL_MAX + 1]; /** ...endpoint classification is a False Negative */
	uint32_t test_FP[SPI_LABEL_MAX + 1]; /** ...endpoint classification is a False Positive */
};

/** Main data root */
struct spi {
	mmatic *mm;                         /** global mm */
	struct spi_options options;         /** spi options */
	bool running;                       /** true if in spi_loop() */
	bool quitting;                      /** true if spi_stop() was called */

	struct event_base *eb;              /** libevent root */
	struct event *evgc;                 /** garbage collector event */

	thash *subscribers;                 /** subscribers of spi events: thash of struct spi_subscribers*/

	tlist *sources;                     /** traffic sources: list of struct spi_source */
	thash *eps;                         /** endpoints: struct spi_ep indexed by file_fd-epa */
	thash *flows;                       /** flows: struct spi_flow indexed by file_fd-epa1-epa2 where epa1 < epa2 */

	tlist *traindata;                   /** signatures for training: list of struct spi_signature */
	tlist *trainqueue;                  /** signatures to be added to traindata */

	struct spi_stats stats;             /** performance measurement */

	void *cdata;                        /** classifiers private data */
	void *vdata;                        /** verdict private data */
};

/** Used for conversion between a void pointer and an spi_event callback address */
union spi_ptr2eventcb_tool {
	void *ptr;
	spi_event_cb_t *func;
};

/** represents listeners of spi events */
struct spi_subscribers {
	tlist *hl;                          /** handler list */
	tlist *ahl;                         /** after handler list */

	/** event aggregation status */
	enum spi_aggstatus {
		SPI_AGG_DISABLED = 0,
		SPI_AGG_READY,
		SPI_AGG_PENDING
	} aggstatus;
};

/** spi event representation */
struct spi_event {
	struct spi *spi;                    /** spi root */
	const char *evname;                 /** event name */
	struct spi_subscribers *ss;         /** subscribers */
	void *arg;                          /** opaque data */
	bool argfree;                       /** free arg after handler call */
};

#endif
