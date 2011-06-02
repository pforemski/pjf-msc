/*
 * spi: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#ifndef _SPID_H_
#define _SPID_H_

#include "settings.h"
#include "datastructures.h"

/** Initialize spi
 * Does initialization of struct spi and setups basic events
 * @param so         options to apply (may be NULL)
 * @retval NULL      failure
 */
struct spi *spi_init(struct spi_options *so);

/** Add traffic source
 * @param type       type of the source (SPI_SOURCE_PCAP, ...)
 * @param label      if not 0, use as learning source for protocol with such numeric ID
 * @param args       source-specific arguments to the source, parsed by relevant handler
 * @retval 0         success
 * @retval 1         failure
 * @retval <0        error specific to source
 */
int spi_source_add(struct spi *spi, spi_source_t type, spi_label_t label, const char *args);

/** Make one iteration of the main spi loop
 * @retval  0        success
 * @retval -1        temporary error
 * @retval  1        permanent error
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

/** Stop spi main loop
 * @param  0         success
 * @param -1         error occured
 */
int spi_stop(struct spi *spi);

/** Free spi memory, close all resources, etc */
void spi_free(struct spi *spi);

#endif
