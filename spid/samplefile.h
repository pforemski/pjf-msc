/*
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#ifndef _SAMPLEFILE_H_
#define _SAMPLEFILE_H_

#include "spid.h"

/** Read sample file into libspi trainqueue
 * @note does not issue spi_trainqueue_commit()
 * @return number of samples read
 * @retval -1 error
 */
int sf_read(struct spid *spid, const char *path);

/** Write libspi samples into file
 * @return number of samples written
 * @retval -1 error
 */
int sf_write(struct spid *spid, const char *path);

#endif
