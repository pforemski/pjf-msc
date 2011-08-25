/*
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#ifndef _SPID_H_
#define _SPID_H_

#include <libpjf/mmatic.h>
#include <libspi/spi.h>

#define SPID_VERSION "0.1"
#define SPID_PIDFILE "/var/run/spid.pid"

struct source {
	char *proto;
	char *cmd;
	bool test;
};

struct spid {
	struct mmatic *mm;             /** mmatic */
	struct spi *spi;               /** libspi handle */
	struct spi_options spi_opts;   /** libspi options */

	thash *proto2label;            /** protocol -> label dict */
	thash *label2proto;            /** label -> proto dict */

	tlist *learn;                  /** list of sources for learning */
	tlist *detect;                 /** list of sources for detection */

	struct {
		bool daemonize;            /** run in foreground? */
		const char *pidfile;       /** PID file */
		const char *signdb;        /** signature database file */
		bool print_prob;           /** print probabilities */
		bool stats;                /** print perf stats */
	} options;
};

/** Return numeric label of given protocol name */
spi_label_t proto_label(const char *proto);

/** Return string protocol name of given numeric label */
const char *label_proto(spi_label_t label);

#endif
