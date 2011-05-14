/*
 * spid: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#include "datastructures.h"
#include "spid.h"
#include "kissp.h"
#include "ep.h"

void kissp_init(struct spid *spid)
{
	spid_subscribe(spid, SPI_EVENT_ENDPOINT_HAS_C_PKTS, kissp_ep_ready);
}

void kissp_ep_ready(struct spid *spid, spid_event_t code, void *data)
{
	struct ep *ep = data;

	dbg(0, "endpoint %s ready!\n", epa_print(ep->epa));
	tlist_flush(ep->pkts);
	ep->has_C = false;
}
