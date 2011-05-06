/*
 * spid: Statistical Packet Inspection
 * Paweł Foremski <pawel@foremski.pl> 2011
 * This software is licensed under GNU GPL version 3
 */

#ifndef _SETTINGS_H_
#define _SETTINGS_H_

/** Number of packets in classification window */
#define SPI_DEFAULT_C 80

/** Max number of packets from single TCP connection */
#define SPI_DEFAULT_P 5

/** Number of payload bytes to analyze */
#define SPI_DEFAULT_N 12

/** Garbage collector interval */
#define SPI_GC_INTERVAL 10

#endif
