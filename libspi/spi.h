/*
 * spi: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

/** @file */

#ifndef _SPI_H_
#define _SPI_H_

#include <pcap.h>
#define __FAVOR_BSD
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "settings.h"
#include "datastructures.h"

/** Initialize spi
 * Does initialization of struct spi and setups basic events
 * @param so         options to apply (may be NULL)
 * @retval NULL      failure
 */
struct spi *spi_init(struct spi_options *so);

/** Add traffic source
 * @param type       type of the source
 * @param label      traffic label: if != 0 and param test is false, use this source for training
 * @param test       use this source for testing
 * @param args       source-specific arguments to the source, parsed by relevant handler
 * @retval 0         success
 * @retval 1         failure
 * @retval <0        error specific to source
 */
int spi_add(struct spi *spi, spi_source_t type, spi_label_t label, bool test, const char *args);

/** Make one iteration of the main spi loop
 * @retval  0        success
 * @retval -1        temporary error
 * @retval  1        permanent error
 * @retval  2        spi_stop() called - quit
 */
int spi_loop(struct spi *spi);

/** Announce a spi event
 * @param evname     spi event name (referenced)
 * @param delay_ms   delay in miliseconds before delivering the event
 * @param arg        opaque data specific to given event
 * @param argfree    do mmatic_freeptr(arg) after event handling / ignoring
 */
void spi_announce(struct spi *spi, const char *evname, uint32_t delay_ms, void *arg, bool argfree);

/** Subscribe to given spi event
 * @param evname     spi event name (referenced)
 * @param cb         event handler - receives code and data from spi_announce()
 * @param aggregate  if true, ignore further events until the first one is handled
 */
void spi_subscribe(struct spi *spi, const char *evname, spi_event_cb_t *cb, bool aggregate);

/** Like spi_subscribe(), but run callback after ordinary handlers finish */
void spi_subscribe_after(struct spi *spi, const char *evname, spi_event_cb_t *cb, bool aggregate);

/** Check if spi event is pending for delivery */
bool spi_pending(struct spi *spi, const char *evname);

/** Stop spi main loop */
void spi_stop(struct spi *spi);

/** Free spi memory, close all resources, etc */
void spi_free(struct spi *spi);

/** Print endpoint address in human-readable format */
static inline const char *spi_epa2a(spi_epaddr_t epa)
{
	static char buf[] = "111.111.111.111:11111";
	struct in_addr addr;

	addr.s_addr = epa >> 16;
	snprintf(buf, sizeof buf, "%s:%u", inet_ntoa(addr), (uint16_t) epa);
	return buf;
}

/** Print source information */
static inline const char *spi_src2a(struct spi_source *src)
{
	char *n;

	if (src->type == SPI_SOURCE_FILE) {
		n = strrchr(src->as.file.path, '/');
		if (n)
			return n + 1;
		else
			return src->as.file.path;
	} else if (src->type == SPI_SOURCE_SNIFF) {
		return src->as.sniff.ifname;
	}
	return "?";
}

/** Print transport protocol name */
#define spi_proto2a(p) (p == SPI_PROTO_UDP ? "UDP" : "TCP")

/** Add given signature to training samples and schedule re-learning
 * @param sign                signature
 * @param label               protocol label
 */
void spi_train(struct spi *spi, struct spi_signature *sign);

/** Add given signature to training samples queue, but don't run re-learning
 * @param sign                signature
 * @param label               protocol label
 */
void spi_trainqueue(struct spi *spi, struct spi_signature *sign);

/** Use the training samples queue and run re-learning immediately */
void spi_trainqueue_commit(struct spi *spi);

/** Free a struct spi_signature
 * @param arg                 address to memory occupied by a struct spi_signature
 */
void spi_signature_free(void *arg);

/** Get False Positive Percentage for given label
 * @retval -1.0    result not available
 */
double spi_stats_fp(struct spi *spi, spi_label_t label);

/** Get False Negative Percentage for given label
 * @retval -1.0    result not available
 */
double spi_stats_fn(struct spi *spi, spi_label_t label);

#endif
