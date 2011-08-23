/*
* Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#include <signal.h>
#include <getopt.h>
#include <libpjf/main.h>
#include <libspi/spi.h>

#include "spid.h"
#include "samplefile.h"

/** Global spid object */
struct spid *spid;

/** Prints spid usage help screen */
static void help(void)
{
	printf("Usage: spid [OPTIONS] [<traffic sources...>]\n");
	printf("\n");
	printf("  Statistical Packet Inspection daemon\n");
	printf("\n");
	printf("Options:\n");
	printf("  --learn=<lspec>  learn according to <lspec>, format:\n");
	printf("                   protocol:file [filter]\n");
	printf("                   protocol:interface [filter]\n");
	printf("  --learndb=<file> learn according to <file>, line format:\n");
	printf("                   protocol file [filter]\n");
	printf("                   protocol interface [filter]\n");
	printf("  --signdb=<file>  signature database file\n");
	printf("  --test=<lspec>   as --learn, but use the source for testing\n");
	printf("  --testdb=<file>  as --learndb, but use all sources for testing\n");
	printf("\n");
	printf("  --kiss-std       use standard KISS algorithm without flow extensions\n");
	printf("  --kiss-linear    use liblinear instead of libsvm\n");
	printf("\n");
	printf("  --verdict-threshold=<t>\n");
	printf("                   treat verdicts with probability below <t>%% as unknowns [%.0f]\n",
		SPI_DEFAULT_VERDICT_THRESHOLD * 100);
	printf("  --verdict-simple use simple verdict issuer\n");
	printf("  --verdict-best   use 'best' verdict issuer\n");
	printf("  --verdict-ewma-len=<num>\n");
	printf("                   set length of EWMA verdict issuer\n");
	printf("\n");
	printf("  --stats          print performance statistics at the end\n");
	printf("  --print-probs    print classification probability\n");
	printf("  --verbose        be verbose (ie. --debug=5)\n");
	printf("  --debug=<num>    set debugging level\n");
	printf("\n");
	//printf("  --daemonize,-d   daemonize and syslog\n");
	//printf("  --pidfile=<path> where to write daemon PID to [%s]\n", SPID_PIDFILE);
	printf("  --help,-h        show this usage help screen\n");
	printf("  --version,-v     show version and copying information\n");
	printf("\n");
	printf("You must provide either --learndb or --signdb option.\n");
	printf("\n");
	printf("Specify <traffic sources> for protocol detection according to:\n");
	printf("  wlan0            interface with default 'tcp or udp' filter\n");
	printf("  \"wlan0 \"         interface without any filters\n");
	printf("  \"wlan0 port 80\"  dump HTTP traffic\n");
	printf("  ./file           pcap file, see above for filters\n");
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

static void free_source(struct source *src)
{
	mmatic_freeptr(src->proto);
	mmatic_freeptr(src->cmd);
}

spi_label_t proto_label(const char *proto)
{
	spi_label_t label;

	if (!proto || !proto[0])
		return 0;

	label = thash_get_uint(spid->proto2label, proto);

	/* register */
	if (label == 0) {
		label = ++spid->label_count;
		thash_set_uint(spid->proto2label, proto, label);
		thash_uint_set(spid->label2proto, label, mmatic_strdup(spid->mm, proto));

		dbg(4, "registered protocol '%s' as label %d\n", proto, label);
	}

	return label;
}

const char *label_proto(spi_label_t label)
{
	const char *proto;

	if (label && (proto = thash_uint_get(spid->label2proto, label)))
		return proto;
	else
		return "unknown";
}

static bool parse_lspec_into_sourcelist(char *arg, tlist *sources, bool test)
{
	char *s;
	struct source *src;

	s = strchr(arg, ':');
	if (!s) {
		dbg(0, "parsing <spec> '%s' failed: no semicolon\n", arg);
		return false;
	} else {
		*s++ = '\0';
	}

	src = mmatic_zalloc(spid->mm, sizeof *src);
	src->proto = mmatic_strdup(spid->mm, arg);
	src->cmd = mmatic_strdup(spid->mm, s);
	src->test = test;

	tlist_push(sources, src);
	return true;
}

static void parse_sspec_into_sourcelist(char *arg, tlist *sources, bool test)
{
	struct source *src;

	src = mmatic_zalloc(spid->mm, sizeof *src);
	src->proto = NULL;
	src->cmd = mmatic_strdup(spid->mm, arg);
	src->test = test;

	tlist_push(sources, src);
}

static bool parse_dbfile_into_sourcelist(const char *path, tlist *sources, bool test)
{
	FILE *fp;
	char buf[BUFSIZ], *s, *p;
	int line = 0;
	struct source *src;

	fp = fopen(path, "r");
	if (!fp) {
		dbg(0, "opening db file '%s' failed: %s\n", path, strerror(errno));
		return false;
	}

	while (fgets(buf, sizeof buf, fp)) {
		line++;

		if (!buf[0] || buf[0] == '\n' || buf[0] == '#')
			continue;

		/* find argument after spaces */
		s = strchr(buf, ' ');
		if (!s) {
			dbg(0, "parsing db file '%s' failed: line %d: syntax error\n", path, line);
			goto fail;
		} else {
			*s++ = '\0';
			while (isspace(*s)) s++;
		}

		/* remove newline char */
		p = strchr(s, '\n');
		if (p) *p = '\0';

		src = mmatic_zalloc(spid->mm, sizeof *src);
		src->proto = mmatic_strdup(spid->mm, buf);
		src->cmd = mmatic_strdup(spid->mm, s);
		src->test = test;

		tlist_push(sources, src);
	}

	fclose(fp);
	return true;

fail:
	fclose(fp);
	return false;
}

/** Parses config
 * @retval 0     all ok
 * @retval 1     ok, but main() should exit (eg. on --version or --help)
 * @retval 2     error, main() should exit (eg. wrong arg. given) */
static int parse_config(int argc, char *argv[])
{
	int i, c;

	static char *short_opts = "hvd";
	static struct option long_opts[] = {
		/* name, has_arg, NULL, short_ch */
		{ "verbose",     0, NULL,  1 },
		{ "debug",       1, NULL,  2 },
		{ "help",        0, NULL,  3 },
		{ "version",     0, NULL,  4 },
		{ "daemonize",   0, NULL,  5 },
		{ "pidfile",     1, NULL,  6 },
		{ "learn",       1, NULL,  7 },
		{ "learndb",     1, NULL,  8 },
		{ "signdb",      1, NULL,  9 },
		{ "kiss-std",    0, NULL, 10 },
		{ "kiss-linear", 0, NULL, 11 },
		{ "verdict-ewma-len",  1, NULL, 12 },
		{ "verdict-simple",    0, NULL, 13 },
		{ "verdict-threshold", 1, NULL, 14 },
		{ "print-probs",       0, NULL, 15 },
		{ "verdict-best",      0, NULL, 16 },
		{ "test",        1, NULL,  17 },
		{ "testdb",      1, NULL,  18 },
		{ "stats",       0, NULL,  19 },
		{ 0, 0, 0, 0 }
	};

	/* set defaults */
	spid->options.daemonize = false;
	spid->options.pidfile = SPID_PIDFILE;

	/* libspi */
	spid->spi_opts.N = SPI_DEFAULT_N;
	spid->spi_opts.P = SPI_DEFAULT_P;
	spid->spi_opts.C = SPI_DEFAULT_C;
	spid->spi_opts.verdict_threshold = SPI_DEFAULT_VERDICT_THRESHOLD;

	for (;;) {
		c = getopt_long(argc, argv, short_opts, long_opts, &i);
		if (c == -1) break; /* end of options */

		switch (c) {
			case  1 : debug = 5; break;
			case  2 : debug = atoi(optarg); break;
			case 'h':
			case  3 : help(); return 1;
			case 'v':
			case  4 : version(); return 1;
			case 'd':
			case  5 : spid->options.daemonize = true; break;
			case  6 : spid->options.pidfile = optarg; break;
			case  7 :
				if (!parse_lspec_into_sourcelist(optarg, spid->learn, false))
					return 2;
				else
					break;
			case  8 :
				if (!parse_dbfile_into_sourcelist(optarg, spid->learn, false))
					return 2;
				else
					break;
			case  9 : spid->options.signdb = mmatic_strdup(spid->mm, optarg); break;
			case 10 : spid->spi_opts.kiss_std = true; break;
			case 11 : spid->spi_opts.kiss_linear = true; break;
			case 12 : spid->spi_opts.verdict_ewma_len = atoi(optarg); break;
			case 13 : spid->spi_opts.verdict_simple = true; break;
			case 14 : spid->spi_opts.verdict_threshold = ((double) atoi(optarg)) / 100.0; break;
			case 15 : spid->options.print_prob = true; break;
			case 16 : spid->spi_opts.verdict_best = true; break;
			case 17 :
				if (!parse_lspec_into_sourcelist(optarg, spid->detect, true))
					return 2;
				else
					break;
			case 18 :
				if (!parse_dbfile_into_sourcelist(optarg, spid->detect, true))
					return 2;
				else
					break;
			case 19 : spid->options.stats = true; break;
			default: help(); return 2;
		}
	}

	/* check if there are any potential learning sources */
	if (tlist_count(spid->learn) == 0 && !spid->options.signdb) {
		dbg(0, "No learning sources. Provide --learn, --learndb or --signdb options.\n");
		dbg(0, "Run spid --help for more info.\n");
		return 2;
	}

	while (argc - optind > 0) {
		parse_sspec_into_sourcelist(argv[optind], spid->detect, false);
		optind++;
	}

	return 0;
}

static bool start_sourcelist(tlist *sources)
{
	struct source *src;
	int rc;
	spi_source_t type;

	tlist_iter_loop(sources, src) {
		if (src->cmd[0] == '.' || src->cmd[0] == '/' || src->cmd[0] == '~' || pjf_isfile(src->cmd) > 0) {
			type = SPI_SOURCE_FILE;
		} else {
			type = SPI_SOURCE_SNIFF;
		}

		if ((rc = spi_add(spid->spi, type, proto_label(src->proto), src->test, src->cmd))) {
			dbg(1, "starting source %s failed (rc=%d)\n", src->cmd, rc);
			return false;
		}
	}

	return true;
}

static bool _verdict_changed(struct spi *spi, const char *evname, void *arg)
{
	struct spi_ep *ep = arg;

	printf("%s: %s is %s",
		spi_src2a(ep->source),
		spi_epa2a(ep->epa),
		label_proto(ep->verdict));

	if (spid->options.print_prob) {
		printf( " %.0f %u\n",
			ep->verdict_prob * 100.0, ep->verdict_count);
	} else {
		printf("\n");
	}

	return true;
}

static bool _spi_finished(struct spi *spi, const char *evname, void *arg)
{
	static int state = 0;

	switch (state) {
		case 0: /* first "finished" */
			/* if nothing to detect, we're done */
			if (tlist_count(spid->detect) == 0) {
				spi_stop(spi);
				return false;
			}

			/* otherwise start sources for detection */
			if (!start_sourcelist(spid->detect))
				exit(3);

			/* detection sources should generate events of verdict change:
			 * subscribe to them - its a point of possible actions */
			spi_subscribe(spid->spi, "endpointVerdictChanged", _verdict_changed, false);

			state++;
			break;
		case 1: /* second "finished" comes after detection sources */
			spi_stop(spi);
			return false;
	}

	return true;
}

/** Stop on Ctrl+C */
static void _sigint(int foo)
{
	dbg(3, "SIGINT received, stopping libspi...\n");
	spi_stop(spid->spi);
}

/** Print stats */
static void _print_stats()
{
	spi_label_t i;
	const char *proto;
	struct spi *spi = spid->spi;
	int ok, err, total;
	double fp, fn;
	double avg_fp = 0.0, avg_fn = 0.0;

	printf("Protocol statistics:\n");
	for (i = 2; i <= spid->label_count; i++) {
		proto = thash_uint_get(spid->label2proto, i);

		fp = spi_stats_fp(spi, i);
		fn = spi_stats_fn(spi, i);

		avg_fp += (fp - avg_fp) / (i - 1);
		avg_fn += (fn - avg_fn) / (i - 1);

		printf("%15s FP %2.0f%% / FN %2.0f%% in %d\n",
			proto, fp, fn, spi->stats.test_is[i]);
	}

	printf("%15s FP %2.0f%% / FN %2.0f%%\n",
		"average", avg_fp, avg_fn);

	ok = spi->stats.test_ok;
	total = spi->stats.test_all;
	err = total - ok;

	printf("Endpoint statistics:\n");
	printf("%15s %4d (%2.0f%%)\n", "valid", ok, 100.0 * ok / total);
	printf("%15s %4d (%2.0f%%)\n", "invalid", err, 100.0 * err / total);
	printf("%15s %4d (%2.0f%%)\n", "total", total, 100.0);
}

int main(int argc, char *argv[])
{
	mmatic *mm;
	int rc;

	/* init */
	mm = mmatic_create();
	spid = mmatic_zalloc(mm, sizeof *spid);
	spid->mm = mm;
	spid->proto2label = thash_create_strkey(NULL, mm);
	spid->label2proto = thash_create_intkey(mmatic_freeptr, mm);
	spid->learn = tlist_create(free_source, mm);
	spid->detect = tlist_create(free_source, mm);

	/* parse arguments */
	rc = parse_config(argc, argv);
	if (rc) return (rc == 2);

	/* init libspi and add learning sources */
	spid->spi = spi_init(&spid->spi_opts);

	/* register "unknown" as 1 */
	proto_label("unknown");

	if (tlist_count(spid->learn) > 0) {
		if (!start_sourcelist(spid->learn))
			return 2;
	}

	if (spid->options.signdb) {
		switch (sf_read(spid, spid->options.signdb)) {
			case -1:
				break;
			case 0:
				dbg(1, "No samples in --signdb\n");
				break;
			default:
				spi_trainqueue_commit(spid->spi);
				break;
		}
	}

	if (tlist_count(spid->learn) == 0 && spid->spi->stats.learned_tq == 0) {
		dbg(0, "No protocol signatures\n");
		return 4;
	}

	/* subscribe to event that might be treated as the moment in which the learning phase
	 * is finished, so we can add sources for detection */
	spi_subscribe(spid->spi, "finished", _spi_finished, true);

	if (spid->options.daemonize)
		pjf_daemonize("spid", spid->options.pidfile);

	signal(SIGINT, _sigint);

	while ((rc = spi_loop(spid->spi)) == 0);

	if (spid->options.signdb && spid->spi->stats.learned_pkt > 0) {
		sf_write(spid, spid->options.signdb);
	}

	if (spid->options.stats)
		_print_stats();

	spi_free(spid->spi);
	mmatic_free(mm);

	return (rc != 2);
}

/*
 * vim: path=.,/usr/include,/usr/local/include,~/local/include
 */
