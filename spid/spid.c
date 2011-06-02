/*
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#include <getopt.h>
#include <libpjf/main.h>
#include <libspi/spi.h>

#include "spid.h"

/** Prints spid usage help screen */
static void help(void)
{
	printf("Usage: spid [OPTIONS]\n");
	printf("\n");
	printf("  Statistical Packet Inspection daemon\n");
	printf("\n");
	printf("Options:\n");
	printf("  --verbose        be verbose (ie. --debug=5)\n");
	printf("  --debug=<num>    set debugging level\n");
	printf("  --daemonize,-d   daemonize and syslog\n");
	printf("  --pidfile=<path> where to write daemon PID to [%s]\n", SPID_PIDFILE);
	printf("  --help,-h        show this usage help screen\n");
	printf("  --version,-v     show version and copying information\n");
	return;
}

/** Prints version and copying information. */
static void version(void)
{
	printf("spid %s\n", SPID_VERSION);
	printf("Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>\n");
	printf("All rights reserved.\n");
	return;
}

/* temporary */
static void add(struct spi *spi, const char *evname, void *arg)
{
	static int done = 0;

	if (done)
		return;
	else
		done = 1;

	dbg(0, "adding dns3\n");
	spi_source_add(spi, SPI_SOURCE_FILE, 0, "/home/pjf/makro/mgr/dumps/udp/dns3");
}

/** Parses Command Line Arguments.
 * @retval 0     error, main() should exit (eg. wrong arg. given)
 * @retval 1     all ok
 * @retval 2     ok, but main() should exit (eg. on --version or --help) */
static int parse_argv(struct spid *spid, int argc, char *argv[])
{
	int i, c;

	static char *short_opts = "hvd";
	static struct option long_opts[] = {
		/* name, has_arg, NULL, short_ch */
		{ "verbose",    0, NULL,  1  },
		{ "debug",      1, NULL,  2  },
		{ "help",       0, NULL,  3  },
		{ "version",    0, NULL,  4  },
		{ "daemonize",  0, NULL,  5  },
		{ "pidfile",    1, NULL,  6  },
		{ 0, 0, 0, 0 }
	};

	/* set defaults */
	spid->options.daemonize = false;
	spid->options.pidfile = SPID_PIDFILE;

	/* libspi */
	spid->spi_opts.N = SPI_DEFAULT_N;
	spid->spi_opts.P = SPI_DEFAULT_P;
	spid->spi_opts.C = SPI_DEFAULT_C;

	for (;;) {
		c = getopt_long(argc, argv, short_opts, long_opts, &i);
		if (c == -1) break; /* end of options */

		switch (c) {
			case  1 : debug = 5; break;
			case  2 : debug = atoi(optarg); break;
			case 'h':
			case  3 : help(); return 2;
			case 'v':
			case  4 : version(); return 2;
			case 'd':
			case  5 : spid->options.daemonize = true; break;
			case  6 : spid->options.pidfile = optarg; break;
			default: help(); return 0;
		}
	}

	spid->spi = spi_init(&spid->spi_opts);

	/* TODO: learning sources */
	if (spi_source_add(spid->spi, SPI_SOURCE_FILE, 1, "/home/pjf/makro/mgr/dumps/udp/dns2"))
		return 0;

	if (spi_source_add(spid->spi, SPI_SOURCE_FILE, 2, "/home/pjf/makro/mgr/dumps/udp/bittorrent2"))
		return 0;

	if (spi_source_add(spid->spi, SPI_SOURCE_FILE, 3, "/home/pjf/makro/mgr/dumps/udp/skype1"))
		return 0;

	if (spi_source_add(spid->spi, SPI_SOURCE_SNIFF, 0, "wlan0"))
		return 0;

	/* TODO: add other files after learning (below is buggy) */
	spi_subscribe(spid->spi, "kisspTraindataUpdated", add, true);

	return 1;
}

int main(int argc, char *argv[])
{
	struct spid *spid;
	mmatic *mm;

	mm = mmatic_create();
	spid = mmatic_zalloc(mm, sizeof *spid);
	spid->mm = mm;

	/* init */
	switch (parse_argv(spid, argc, argv)) { case 0: return 1; case 2: return 0; }

	if (spid->options.daemonize)
		pjf_daemonize("spid", spid->options.pidfile);

	while (spi_loop(spid->spi) == 0);

	spi_free(spid->spi);
	mmatic_free(mm);

	return 1;
}

/*
 * vim: path=.,/usr/include,/usr/local/include,~/local/include
 */
