/*
 * spid: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#ifndef _EP_H_
#define _EP_H_

#include "datastructures.h"

/** Destroy endpoint memory */
void ep_destroy(struct ep *ep);

/** Save packet of endpoint given by ip and port
 * @param pkt        prepared pkt struct - packet is copied to ep->mm
 * @param proto      endpoint protocol
 * @param ip         endpoint ip address
 * @param port       endpoint port number
 * @return           endpoint structure
 */
struct ep *ep_new_pkt(const struct pkt *pkt, proto_t proto, uint32_t ip, uint16_t port);

#endif
