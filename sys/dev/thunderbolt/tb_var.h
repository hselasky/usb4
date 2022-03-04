/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2022 Scott Long
 * All rights reserved.
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
 *
 * Thunderbolt firmware connection manager functions.
 *
 * $FreeBSD$
 */

#ifndef _TB_VAR_H
#define _TB_VAR_H

typedef struct {
	int8_t link;
	int8_t depth;
} tb_addr_t;

struct icm_event {
	TAILQ_ENTRY(icm_event)	link;
	uint32_t		buf[];
};

MALLOC_DECLARE(M_THUNDERBOLT);

#define TB_VENDOR_LEN	48
#define TB_MODEL_LEN	48
#define TB_MAX_LINKS	4
#define TB_MAX_DEPTH	6

struct icm_device {
	TAILQ_ENTRY(icm_device)	link;
	int8_t		conn_key;
	uint8_t		conn_id;
	tb_route_t	route;
	tb_addr_t	ld;
	uint8_t		EPUID[16];
	uint16_t	flags;
#define TBDEV_LINK_DUAL		(1 << 0)
#define TBDEV_DEPTH_FIRST	(1 << 1)
#define TBDEV_LANE_20G		(1 << 2)
#define TBDEV_NO_APPROVE	(1 << 4)
#define TBDEV_REJECTED		(1 << 5)
#define TBDEV_ATBOOT		(1 << 6)
	uint8_t		power;
#define TBDEV_POWER_SELF	0
#define TBDEV_POWER_NORM	1
#define TBDEV_POWER_HIGH	2
#define TBDEV_POWER_UNK		3
	uint8_t		security;
	uint8_t		vendor[TB_VENDOR_LEN];
	uint8_t		model[TB_MODEL_LEN];

#define TB_NODENAME_LEN		17
	char			nodename[TB_NODENAME_LEN];
	struct sysctl_ctx_list	ctx;
	struct sysctl_oid	*tree;
};

struct icm_command;
typedef void (*icm_callback_t)(struct icm_softc *, struct icm_command *, void *);

struct icm_command {
	struct nhi_cmd_frame	*nhicmd;
	u_int			flags;
#define ICM_CMD_POLL_COMPLETE	(1 << 0)
	uint8_t			resp_buffer[NHI_RING0_FRAME_SIZE];
	int			resp_len;
	u_int			resp_code;
	icm_callback_t		callback;
	void			*callback_arg;
};

#define TB_FWSTRING_LEN		16
struct icm_softc {
	struct nhi_softc	*sc;
	device_t		dev;
	u_int			debug;
	u_int			flags;
#define TBSC_DRIVER_WAITING	(1 << 0)
#define TBSC_DRIVER_READY	(1 << 1)
	TAILQ_HEAD(, icm_device) icm_devs;

	struct mtx		mtx;
	struct nhi_cmd_frame	*tx_inflight_cmd;
	TAILQ_HEAD(, nhi_cmd_frame)	tx_queue;
	struct nhi_ring_pair	*ring0;

	TAILQ_HEAD(, icm_event)	cmevent_list;
	struct task		cmevent_task;
	struct taskqueue	*taskqueue;
	struct intr_config_hook	ich;

	int			user_approve;
	uint8_t			sec;
	uint8_t			acl;

	struct sysctl_ctx_list	sysctl_ctx;
	struct sysctl_oid	*sysctl_tree;
	char			fw_string[TB_FWSTRING_LEN];
};

int icm_attach(struct nhi_softc *);
void icm_detach(struct nhi_softc *);
int icm_init(struct nhi_softc *);
int icm_driver_unload(struct nhi_softc *);
int icm_get_uuid(struct nhi_softc *);

static __inline uint32_t
tb_calc_crc(void *data, u_int len)
{
	return ( ~ (calculate_crc32c(~0L, data, len)));
}

static __inline void *
icm_get_frame_data(struct icm_command *icmd)
{
	return ((void *)icmd->nhicmd->data);
}

#endif /* _TB_VAR_H */
