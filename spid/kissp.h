/*
 * spid: Statistical Packet Inspection: KISS+ classifier
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#ifndef _KISSP_H_
#define _KISSP_H_

#include "datastructures.h"

/** Initialize KISS+ classifier */
void kissp_init(struct spid *spid);

/** Receives events of endpoint being ready for classification
 * @param code      SPI_EVENT_ENDPOINT_HAS_C_PKTS
 * @param data      struct ep pointer
 */
void kissp_ep_ready(struct spid *spid, spid_event_t code, void *data);

#endif
