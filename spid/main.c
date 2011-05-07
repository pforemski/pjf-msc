/*
 * spid: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#include <libpjf/main.h>

#include "datastructures.h"
#include "spid.h"

int main(int argc, char *argv[])
{
	struct spid *spid;
	struct spid_options so;

	debug = 10;

	so.N = SPI_DEFAULT_N;
	so.P = SPI_DEFAULT_P;
	so.C = SPI_DEFAULT_C;
	spid = spid_init(&so);

	if (spid_source_add(spid, SPI_SOURCE_SNIFF, 0, "wlan0"))
		return 1;

	/* TODO: libevent epoll error: Epoll ADD(1) on fd 8 failed */
//	if (spid_source_add(spid, SPI_SOURCE_FILE, 0, "/home/pjf/makro/mgr/dumps/udp/dns2"))
//		return 1;

	while (spid_loop(spid) == 0);

	return 1;
}

/*
 * vim: path=.,/usr/include,/usr/local/include,~/local/include
 */
