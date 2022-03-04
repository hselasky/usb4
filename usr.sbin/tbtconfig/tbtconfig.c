/* $FreeBSD$ */
/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2022 Scott Long
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/nv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>

#include "../../sys/dev/thunderbolt/tb_ioctl.h"

static int verbose = 0;

static int
usage(void)
{
	fprintf(stderr, "usage: %s [-v] <command> ...\n", getprogname());
	return (1);
}

static int
tbt_open(void)
{
	char path[MAXPATHLEN];

	snprintf(path, sizeof(path), "/dev/%s", TBT_DEVICE_NAME);
	return (open(path, O_RDWR));
}

int
main(int argc, char **argv)
{
	nvlist_t *nv;
	size_t len;
	struct tbt_ioc ioc;
	void *nvlpacked;
	char *buf, *iface;
	int error, fd, ch;

	while ((ch = getopt(argc, argv, "vh?")) != -1) {
		switch (ch) {
		case 'v':
			verbose = 1;
		case 'h':
		case '?':
			usage();
			return (1);
		}
	}

	fd = tbt_open();
	if (fd < 0)
		err(1, "could not open Thunderbolt control device\n");

	nv = nvlist_create(NV_FLAG_NO_UNIQUE);
	nvlist_add_string(nv, TBT_DISCOVER_TYPE, TBT_DISCOVER_IFACE);

	nvlpacked = nvlist_pack(nv, &len);
	if (nvlpacked == NULL)
		err(1, "could not create nvlist\n");

	buf = malloc(TBT_IOCMAXLEN);
	ioc.size = TBT_IOCMAXLEN;
	ioc.len = len;
	ioc.data = nvlpacked;

	error = ioctl(fd, TBT_DISCOVER, (caddr_t)&ioc);
	if (error)
		err(1, "ioctl returned %d\n", error);

	nvlist_destroy(nv);

	nv = nvlist_unpack(ioc.data, ioc.len, NV_FLAG_NO_UNIQUE);
	if (nv == NULL)
		err(1, "new nvlist couldn't be unpacked\n");

	while (nvlist_exists(nv, TBT_DISCOVER_IFACE)) {
		iface = nvlist_take_string(nv, TBT_DISCOVER_IFACE);
		printf("%s = %s\n", TBT_DISCOVER_IFACE, iface);
	}

	free(buf);
	free(nvlpacked);
	nvlist_destroy(nv);

	return (0);
}
