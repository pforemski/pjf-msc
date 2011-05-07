/*
 * spid: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#ifndef _SPID_H_
#define _SPID_H_

#include "settings.h"
#include "datastructures.h"

/** Initialize spid
 * Does initialization of struct spid and setups basic events
 * @param so         options to apply (may be NULL)
 * @retval NULL      failure
 */
struct spid *spid_init(struct spid_options *so);

/** Add traffic source
 * @param type       type of the source (SPI_SOURCE_PCAP, ...)
 * @param label      if not 0, use as learning source for protocol with such numeric ID
 * @param args       source-specific arguments to the source, parsed by relevant handler
 * @retval 0         success
 * @retval 1         failure
 * @retval <0        error specific to source
 */
int spid_source_add(struct spid *spid, spid_source_t type, label_t label, const char *args);

/** Make one iteration of the main spid loop
 * @retval  0        success
 * @retval -1        temporary error
 * @retval  1        permanent error
 */
int spid_loop(struct spid *spid);

/** Announce a spid event
 * @param code       event code
 * @param data       opaque data specific to given event
 * @param delay_ms   delay in miliseconds before delivering the event
 */
void spid_announce(struct spid *spid, spid_event_t code, void *data, uint32_t delay_ms);

/** Subscribe to given spid event
 * @param code       event code
 * @param cb         event handler - receives code and data from spid_announce()
 */
void spid_subscribe(struct spid *spid, spid_event_t code, spid_event_cb_t *cb);

#endif
