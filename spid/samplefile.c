/*
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#include "samplefile.h"

int sf_read(struct spid *spid, const char *path)
{
	FILE *fp;
	char buf[1024], *cur, *next;
	struct spi_signature *sign;
	int i, j = 0, cols = 0, line = 0;

	fp = fopen(path, "r");
	if (!fp) {
		dbg(0, "%s: opening for read failed: %m\n", path);
		return -1;
	}

	while (fgets(buf, sizeof buf, fp)) {
		line++;

		/* skip comments, empty lines, etc */
		if (!buf[0] || buf[0] == '#' || buf[0] == '\n')
			continue;

		/* determine number of columns */
		if (cols == 0) {
			for (i = 0; buf[i]; i++) {
				if (buf[i] == ' ')
					cols++;
			}

			/* +1 because "there is one space between two columns"
			 * +1 for the -1 ending
			 * -1 for the proto name */
			cols = cols + 1 + 1 - 1;
		}

		sign = mmatic_zalloc(spid->mm, sizeof *sign);
		sign->c = mmatic_zalloc(spid->mm, cols * sizeof *(sign->c));

		/* read proto name */
		cur = buf;
		next = strchr(cur, ' ');
		if (!next) continue;
		*next++ = '\0';
		sign->label = proto_label(cur);

		/* read coordinates */
		for (i = 0; i < cols - 1; i++) {
			cur = next;
			next = strchr(cur, ' ');
			if (next) *next++ = '\0';

			sscanf(cur, "%lg", &sign->c[i].value);
			sign->c[i].index = i + 1;

			if (!next) {
				sign->c[i + 1].index = -1;
				break;
			}
		}

		if (i == cols - 2) {
			spi_trainqueue_add(spid->spi, sign);
			j++;
		} else {
			dbg(2, "%s#%d: invalid number of columns (%d, expected %d)\n",
				path, line, i, cols-2);
		}
	}

	fclose(fp);
	dbg(1, "%s: read %d samples into trainqueue\n", path, j);

	return j;
}

int sf_write(struct spid *spid, const char *path)
{
	FILE *fp;
	struct spi_signature *sign;
	int i, j = 0;

	fp = fopen(path, "w");
	if (!fp) {
		dbg(0, "%s: opening for write failed: %m\n", path);
		return -1;
	}

	tlist_iter_loop(spid->spi->traindata, sign) {
		fprintf(fp, "%s", label_proto(sign->label));
		for (i = 0; sign->c[i].index != -1; i++)
			fprintf(fp, " %g", sign->c[i].value);
		fprintf(fp, "\n");
		j++;
	}

	dbg(1, "%s: written %d samples\n", path, j);
	return j;
}
