/*
 * spi: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#ifndef _SOURCE_H_
#define _SOURCE_H_

#include "datastructures.h"

/** Destroy source memory */
void source_destroy(struct spi_source *source);

/** Initialize a PCAP file source
 * @param args    just file path
 * @retval -1     pcap error (see dbg messages)
 */
int source_file_init(struct spi_source *source, const char *args);

/** Handle new packets on a PCAP file source */
void source_file_read(int fd, short evtype, void *arg);

/** Close a file source */
void source_file_close(struct spi_source *source);

/** Initialize a live pcap sniffer source
 * @param args    interface
 * @retval -1     pcap error (see dbg messages)
 */
int source_sniff_init(struct spi_source *source, const char *args);

/** Handle new packets on a live pcap sniffer source */
void source_sniff_read(int fd, short evtype, void *arg);

#endif
