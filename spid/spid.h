/*
 * spid: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#ifndef _SPID_H_
#define _SPID_H_

#include "datastructures.h"

/** Initialize spid
 * Does initialization of struct spid and contents, parses options and sets up events.
 *
 * @param argc       number of elements in argv
 * @param argv       command-line arguments (may be NULL)
 * @param so         options to apply before argv (may be NULL)
 * @retval NULL      failure
 */
struct spid *spid_init(int argc, const char *argv[], struct spid_options *so);

/** Make one iteration of the main spid loop
 * @retval  0        success
 * @retval -1        failure, may be temporary
 * @retval  1        failure, permanent error
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
