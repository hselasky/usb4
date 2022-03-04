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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_thunderbolt.h"

/* Thunderbolt firmware and connection manager interface */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#include <sys/sbuf.h>
#include <sys/sysctl.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/taskqueue.h>
#include <sys/gsb_crc32.h>
#include <sys/endian.h>

#include <machine/bus.h>
#include <machine/stdarg.h>

#include <dev/thunderbolt/nhi_reg.h>
#include <dev/thunderbolt/nhi_var.h>
#include <dev/thunderbolt/tb_reg.h>
#include <dev/thunderbolt/tb_var.h>
#include <dev/thunderbolt/tbcfg_reg.h>
#include <dev/thunderbolt/router_var.h>
#include <dev/thunderbolt/tb_debug.h>

static int icm_alloc_cmd(struct icm_softc *, struct icm_command **);
static void icm_free_cmd(struct icm_softc *, struct icm_command *);
static void icm_post_init(void *);
static int icm_check_driver_ready(struct icm_softc *);
static void icm_free_device(struct icm_softc *, struct icm_device *);
static int icm_send_driver_ready(struct icm_softc *);
static int icm_driver_ready_cb(struct icm_softc *, struct icm_command *);
static void icm_get_devroute_cb(struct icm_softc *, struct icm_command *,
    void *);
static int icm_approve_device_v1(struct icm_softc *, struct icm_device *);
static int icm_approve_device_v2(struct icm_softc *, struct icm_device *);
static void icm_approve_device_cb(struct icm_softc *, struct icm_command *,
    void *);
static void icm_prepare_cmd(struct icm_softc *, struct icm_command *, int,
    int);
static int icm_tx_schedule(struct icm_softc *, struct icm_command *);
static int icm_tx_schedule_polled(struct icm_softc *, struct icm_command *);
static void icm_command_complete(struct icm_softc *, void *);
static void icm_event_devconn_v1(struct icm_softc *, struct icm_event *);
static void icm_event_devconn_v2(struct icm_softc *, struct icm_event *);
static void icm_event_devdisconn_v1(struct icm_softc *, struct icm_event *);
static void icm_event_devdisconn_v2(struct icm_softc *, struct icm_event *);
static void icm_event_domconn(struct icm_softc *, struct icm_event *);
static void icm_event_domdisconn(struct icm_softc *, struct icm_event *);
static void icm_event_rtd3(struct icm_softc *, struct icm_event *);
static void icm_cmevent_task(void *, int);
static int icm_device_create_sysctls(struct icm_softc *, struct icm_device *);

static nhi_ring_cb_t icm_tx_done_intr;
static nhi_ring_cb_t icm_rx_resp_intr;
static nhi_ring_cb_t icm_rx_notify_intr;

#define ICM_DEFAULT_RETRIES	0
#define ICM_DEFAULT_TIMEOUT	2

MALLOC_DEFINE(M_THUNDERBOLT, "thunderbolt", "memory for thunderbolt");

static int
icm_register_interrupts(struct icm_softc *sc)
{
	struct nhi_dispatch tx[] = { { PDF_CM_REQ, icm_tx_done_intr, sc },
				     { 0, NULL, NULL } };
	struct nhi_dispatch rx[] = { { PDF_CM_RESP, icm_rx_resp_intr, sc },
				     { PDF_CM_EVENT, icm_rx_notify_intr, sc },
				     { 0, NULL, NULL } };

	return (nhi_register_pdf(sc->ring0, tx, rx));
}

/*
 * The ICM can only handle one command at a time, but we might get multiple
 * requests in at once, especially during device discovery.  Instead of
 * teaching every consider how to deal with flow control and busy states,
 * allow them to act like multiple commands can be in flight at once, and
 * move the flow control into a scheduling layer.  This only works as long
 * as the NHI layer has free commands, but its default command pool is large
 * enough that it shouldn't be a problem in practice.
 */
static int
icm_alloc_cmd(struct icm_softc *icmsc, struct icm_command **cmd)
{
	struct icm_command *icmd;

	tb_debug(icmsc, DBG_TB|DBG_EXTRA, "icm_alloc_cmd\n");

	KASSERT(cmd != NULL, ("cmd cannot be NULL"));

	icmd = malloc(sizeof(*icmd), M_THUNDERBOLT, M_ZERO|M_NOWAIT);

	if (icmd == NULL) {
		tb_debug(icmsc, DBG_TB, "Cannot allocate cmd/response\n");
		return (ENOMEM);
	}

	icmd->nhicmd = nhi_alloc_tx_frame(icmsc->ring0);
	if (icmd->nhicmd == NULL) {
		tb_debug(icmsc, DBG_TB, "Cannot allocate cmd\n");
		free(icmd, M_THUNDERBOLT);
		return (EBUSY);
	}
	*cmd = icmd;
	tb_debug(icmsc, DBG_TB, "Allocated command with index %d\n",
	    icmd->nhicmd->idx);

	return (0);
}

static void
icm_free_cmd(struct icm_softc *icmsc, struct icm_command *cmd)
{

	tb_debug(icmsc, DBG_TB|DBG_EXTRA, "icm_free_cmd\n");

	KASSERT(cmd != NULL, ("cmd cannot be NULL"));

	tb_debug(icmsc, DBG_TB, "Freeing command with index %d\n",
	    cmd->nhicmd->idx);
	nhi_free_tx_frame(icmsc->ring0, cmd->nhicmd);
	free(cmd, M_THUNDERBOLT);
}

int
icm_attach(struct nhi_softc *nsc)
{
	struct icm_softc *icmsc;
	int val;

	icmsc = malloc(sizeof(*icmsc), M_THUNDERBOLT, M_NOWAIT|M_ZERO);
	if (icmsc == NULL)
		return (ENOMEM);

	icmsc->sc = nsc;
	nsc->icmsc = icmsc;
	icmsc->dev = nsc->dev;
	icmsc->debug = nsc->debug;
	icmsc->ring0 = nsc->ring0;

	mtx_init(&icmsc->mtx, "tbmtx", "TB3 connection manager", MTX_DEF);
	TAILQ_INIT(&icmsc->icm_devs);
	TAILQ_INIT(&icmsc->tx_queue);

	sysctl_ctx_init(&icmsc->sysctl_ctx);
	icmsc->sysctl_tree = SYSCTL_ADD_NODE(&icmsc->sysctl_ctx,
	    SYSCTL_CHILDREN(nsc->sysctl_tree), OID_AUTO, "thunderbolt",
	    CTLFLAG_RD, 0, "thunderbolt node");
	if (icmsc->sysctl_tree == NULL) {
		tb_debug(icmsc, DBG_TB, "Failed to create sysctl "
		    "context for thunderbolt\n");
		return (EINVAL);
	}
	SYSCTL_ADD_U16(&icmsc->sysctl_ctx, SYSCTL_CHILDREN(icmsc->sysctl_tree),
	    OID_AUTO, "maxdevs", CTLFLAG_RD, &nsc->path_count, 0,
	    "Maximum number of devices");

	icmsc->user_approve=1;
	if (TUNABLE_INT_FETCH("hw.nhi.thunderbolt.auto_approve", &val) != 0)
		icmsc->user_approve = !!val;

	SYSCTL_ADD_INT(&icmsc->sysctl_ctx, SYSCTL_CHILDREN(icmsc->sysctl_tree),
	    OID_AUTO, "auto_approve", CTLFLAG_RW, &icmsc->user_approve, 0,
	    "Automatically approve device connections");

	bzero(icmsc->fw_string, TB_FWSTRING_LEN);
	SYSCTL_ADD_STRING(&icmsc->sysctl_ctx, SYSCTL_CHILDREN(icmsc->sysctl_tree),
	    OID_AUTO, "firmware_version", CTLFLAG_RD, icmsc->fw_string, 0,
	    "Thunderbolt Connection Manager Firmware Version");

	icmsc->taskqueue = taskqueue_create("icm_event", M_WAITOK,
	    taskqueue_thread_enqueue, &icmsc->taskqueue);
	taskqueue_start_threads(&icmsc->taskqueue, 1, PI_DISK, "tbevt_tq");

	TASK_INIT(&icmsc->cmevent_task, 0, icm_cmevent_task, icmsc);
	TAILQ_INIT(&icmsc->cmevent_list);

	icm_register_interrupts(icmsc);

	return (0);
}

void
icm_detach(struct nhi_softc *nsc)
{
	struct icm_softc *icmsc;
	struct icm_device *dev;

	if (nsc->icmsc == NULL)
		return;

	icmsc = nsc->icmsc;

	/* XXX Drain? */
	if (icmsc->taskqueue)
		taskqueue_free(icmsc->taskqueue);

	/*
	 * Freeing can be recursive, so a simple foreach loop
	 * might not be safe.
	 */
	while ((dev = TAILQ_FIRST(&icmsc->icm_devs)) != NULL)
		icm_free_device(icmsc, dev);

	if (icmsc->sysctl_tree != NULL) {
		sysctl_ctx_free(&icmsc->sysctl_ctx);
		icmsc->sysctl_tree = NULL;
	}

	mtx_destroy(&icmsc->mtx);
	free(icmsc, M_THUNDERBOLT);
	nsc->icmsc = NULL;

	return;
}

static void
icm_free_device(struct icm_softc *icmsc, struct icm_device *dev)
{
	struct icm_device *srchdev, *tmpdev;
	u_int link, depth;

	tb_debug(icmsc, DBG_TB, "icm_free_device");

	if (dev == NULL)
		return;

	/*
	 * The bus on each link relies on hops, so if a lower numbered
	 * device goes away, i.e. a parent, then the children need to be
	 * removed as well.
	 * XXX Assumes that the list is ordered.
	 */
	link = dev->ld.link;
	depth = dev->ld.depth;
	srchdev = dev;
	TAILQ_FOREACH_FROM_SAFE(srchdev, &icmsc->icm_devs, link, tmpdev) {
		if ((srchdev->ld.link == link) &&
		    (srchdev->ld.depth == depth + 1))
			icm_free_device(icmsc, srchdev);
	}

	tb_debug(icmsc, DBG_TB|DBG_FULL, "Freeing device at %08x%08x\n",
	    dev->route.hi, dev->route.lo);
	if (dev->tree != NULL)
		sysctl_ctx_free(&dev->ctx);
	TAILQ_REMOVE(&icmsc->icm_devs, dev, link);
	free(dev, M_THUNDERBOLT);
}

int
icm_init(struct nhi_softc *nsc)
{
	struct icm_softc *icmsc;
	int error;

	icmsc = nsc->icmsc;
	tb_debug(icmsc, DBG_TB, "TB Init\n");

	icmsc->flags = TBSC_DRIVER_WAITING;

	/*
	 * Defer the parts of initialization that require
	 * delays and retries.
	 */
	icmsc->ich.ich_func = icm_post_init;
	icmsc->ich.ich_arg = icmsc;
	if ((error = config_intrhook_establish(&icmsc->ich)) != 0) {
		tb_printf(icmsc, "Failed to establish config hook\n");
		return (error);
	}

	error = icm_send_driver_ready(icmsc);

	return (error);
}

/*
 * The intrhook will be run immediately when the driver is loaded post-boot,
 * in which case it's likely that this callback will be called before the
 * command completes.  Therefore, don't unconditionally release the hook
 * here, release it only when we know that the DRIVER_READY has been
 * completed.
 */
static void
icm_post_init(void *arg)
{
	struct icm_softc *icmsc;

	icmsc = (struct icm_softc *)arg;
	tb_debug(icmsc, DBG_TB, "icm_post_init\n");

	if (icm_check_driver_ready(icmsc) != 0)
		tb_debug(icmsc, DBG_TB|DBG_FULL, "ICM not ready yet\n");

	return;
}

/*
 * This is called from the intrhook callback context and the DRIVER_READY
 * completion callback.
 */
static int
icm_check_driver_ready(struct icm_softc *icmsc)
{

	if ((icmsc->flags & TBSC_DRIVER_READY) == 0)
		return (EBUSY);

	mtx_lock(&icmsc->mtx);
	if (icmsc->flags & TBSC_DRIVER_WAITING) {
		config_intrhook_disestablish(&icmsc->ich);
		icmsc->ich.ich_func = NULL;
		icmsc->flags &= ~TBSC_DRIVER_WAITING;
	}
	mtx_unlock(&icmsc->mtx);

	return (0);
}

static int
icm_send_driver_ready(struct icm_softc *icmsc)
{
	struct icm_driver_ready *msg;
	struct icm_command *cmd;
	int error;

	tb_debug(icmsc, DBG_TB, "Sending DRIVER_READY\n");

	if ((error = icm_alloc_cmd(icmsc, &cmd)) != 0) {
		tb_printf(icmsc,
		    "Cannot allocate cmd/resp for DRIVER_READY\n");
		return (ENOMEM);
	}

	msg = icm_get_frame_data(cmd);
	bzero(msg, sizeof(*msg));
	msg->hdr.cmd = ICM_CMD_DRIVER_READY;
	cmd->resp_code = ICM_RESP_DRIVER_READY;
	icm_prepare_cmd(icmsc, cmd, sizeof(*msg), NHI_RING0_FRAME_SIZE);

	error = icm_tx_schedule_polled(icmsc, cmd);
	if (error == EWOULDBLOCK) {
		tb_printf(icmsc, "ERROR: Timeout sending DRIVER_READY\n");
	} else if (error == EBUSY) {
		tb_printf(icmsc, "ERROR: No queue space for DRIVER_READY\n");
	} else if (error != 0) {
		tb_printf(icmsc, "Error %d sending DRIVER_READY\n", error);
	}

	if (error == 0)
		error = icm_driver_ready_cb(icmsc, cmd);

	return (error);
}

static int
icm_driver_ready_cb(struct icm_softc *icmsc, struct icm_command *cmd)
{
	struct nhi_softc *nsc;
	struct icm_response_hdr *hdr;
	struct icm_driver_ready_resp_v1 *r1;
	struct icm_driver_ready_resp_v2 *r2;
	uint8_t *resp;
	int error = 0, connmode;

	nsc = icmsc->sc;
	resp = (uint8_t *)cmd->resp_buffer;
	hdr = (struct icm_response_hdr *)resp;
	if (hdr->flags & ICM_DRVREADY_ERROR) {
		tb_printf(icmsc, "Firmware error on DRIVER_READY\n");
		error = ENXIO;
		goto out;
	}

	if (NHI_IS_AR(nsc)) {
		r1 = (struct icm_driver_ready_resp_v1 *)resp;
		icmsc->sec = r1->security_level & ICM_DRVREADY_SECURITY_MASK;
		icmsc->acl = (r1->security_level & ICM_DRVREADY_ACL_MASK) >>
		    ICM_DRVREADY_ACL_SHIFT;
		connmode = hdr->flags & ICM_DRVREADY_CONNMODE_MASK;
		snprintf(icmsc->fw_string, TB_FWSTRING_LEN, "%d.%d.0",
		    r1->rom_version, r1->ram_version);
	} else { /* NHI_IS_TR(nsc) || NHI_IS_ICL(nsc) */
		r2 = (struct icm_driver_ready_resp_v2 *)resp;
		icmsc->sec = r2->security_level & ICM_DRVREADY_V2_SECURITY_MASK;
		icmsc->acl = (r2->security_level & ICM_DRVREADY_V2_ACL_MASK) >>
		    ICM_DRVREADY_V2_ACL_SHIFT;
		connmode = hdr->flags & ICM_DRVREADY_CONNMODE_MASK;
		snprintf(icmsc->fw_string, TB_FWSTRING_LEN, "%d.%d.%d",
		    r2->rom_version, r2->ram_version, r2->nvm_version);
	}

	if (icmsc->acl > ICM_DRVREADY_ACL_MAX)
		icmsc->acl = 0;

	tb_printf(icmsc, "Firmware version %s\n", icmsc->fw_string);
	tb_printf(icmsc, "Security mode: %s (%#x)\n", tb_get_string(icmsc->sec,
	    tb_security_level), (u_int)icmsc->sec);
	tb_debug(icmsc, DBG_TB, "ACL index: %d\n", icmsc->acl);
	tb_debug(icmsc, DBG_TB, "Connection mode: %s\n",
	    tb_get_string(connmode, tb_rdy_connmode));

	/* Signal that the DRIVER_READY came in, release the intrhook */
	icmsc->flags |= TBSC_DRIVER_READY;
	icm_check_driver_ready(icmsc);

out:
	icm_free_cmd(icmsc, cmd);
	if (error)
		icm_driver_unload(nsc);

	return (error);
}

int
icm_driver_unload(struct nhi_softc *nsc)
{
	struct icm_softc *icmsc;
	uint32_t status;
	int error;

	icmsc = nsc->icmsc;
	tb_debug(icmsc, DBG_TB, "Sending DRIVER_UNLOAD_DISCONNECT\n");
	error = nhi_inmail_cmd(nsc, INMAILCMD_DRIVER_UNLOAD_DISCONNECT, 0);
	if (error) {
		nhi_outmail_cmd(nsc, &status);
		tb_debug(icmsc, DBG_TB, "driver unload failed error= %d. "
		    "mailbox status= 0x%x\n", error, status);
	}
	return (error);
}

/*
 * Send a request to approve a PCI device.  This happens when the user
 * selects the "User" security mode.
 */
static int
icm_approve_device_v1(struct icm_softc *icmsc, struct icm_device *dev)
{
	struct icm_approve_pci_v1	*msg;
	struct icm_command *cmd;
	int error;

	tb_debug(icmsc, DBG_TB, "Sending APPROVE_PCI for device at %d, %d\n",
	    dev->ld.link, dev->ld.depth);

	if ((error = icm_alloc_cmd(icmsc, &cmd)) != 0) {
		tb_printf(icmsc, "Cannot allocate cmd/resp for APPROVE_PCI\n");
		return (error);
	}

	msg = icm_get_frame_data(cmd);
	bzero(msg, sizeof(*msg));
	msg->hdr.cmd = ICM_CMD_APPROVE_PCI;
	bcopy(dev->EPUID, msg->EPUID, 16);
	msg->conn_id = dev->conn_id;
	msg->conn_key = dev->conn_key;

	cmd->callback = icm_approve_device_cb;
	cmd->callback_arg = dev;
	cmd->resp_code = ICM_RESP_APPROVE_PCI;

	icm_prepare_cmd(icmsc, cmd, sizeof(*msg), ICM_APPROVE_PCI_RESP_1_LEN);

	mtx_lock(&icmsc->mtx);
	error = icm_tx_schedule(icmsc, cmd);
	mtx_unlock(&icmsc->mtx);
	return (error);
}

/*
 * TR and ICL version of APPROVE_PCI
 */
static int
icm_approve_device_v2(struct icm_softc *icmsc, struct icm_device *dev)
{
	struct icm_approve_pci_v2	*msg;
	struct icm_command *cmd;
	int error;

	tb_debug(icmsc, DBG_TB, "Sending APPROVE_PCI for device at %08x%08x\n",
	    dev->route.hi, dev->route.lo);

	if ((error = icm_alloc_cmd(icmsc, &cmd)) != 0) {
		tb_printf(icmsc, "Cannot allocate cmd/resp for APPROVE_PCI\n");
		return (error);
	}

	msg = icm_get_frame_data(cmd);
	bzero(msg, sizeof(*msg));
	msg->hdr.cmd = ICM_CMD_APPROVE_PCI;
	bcopy(dev->EPUID, msg->EPUID, 16);
	msg->conn_id = dev->conn_id;
	msg->route.hi = dev->route.hi;
	msg->route.lo = dev->route.lo;

	cmd->callback = icm_approve_device_cb;
	cmd->callback_arg = dev;
	cmd->resp_code = ICM_RESP_APPROVE_PCI;

	icm_prepare_cmd(icmsc, cmd, sizeof(*msg), ICM_APPROVE_PCI_RESP_2_LEN);

	mtx_lock(&icmsc->mtx);
	error = icm_tx_schedule(icmsc, cmd);
	mtx_unlock(&icmsc->mtx);
	return (error);
}

/*
 * Completion for APPROVE_PCI.  Even though there are AR and TR/ICL variants,
 * we can use the same routine here since all we care about is the header.
 */
static void
icm_approve_device_cb(struct icm_softc *icmsc, struct icm_command *cmd,
    void *arg)
{
	struct icm_response_hdr *hdr;
	struct icm_device *dev;

	KASSERT(arg != NULL, ("Invalid device in icm_approve_device_cb"));
	dev = (struct icm_device *)arg;
	hdr = (struct icm_response_hdr *)cmd->resp_buffer;

	tb_debug(icmsc, DBG_TB, "APPROVE_PCI response received for "
	    "%08x%08x\n", dev->route.hi, dev->route.lo);

	if (hdr->flags & ICM_APPROVEPCI_ERROR)
		tb_printf(icmsc, "Error approving device at %08x%08x\n",
		    dev->route.hi, dev->route.lo);

	icm_free_cmd(icmsc, cmd);
}

/*
 * Get the 64bit route string for the device.  It's only useful for AR
 * hosts since those hosts don't use the route as the primary key.
 */
static int
icm_get_devroute(struct icm_softc *icmsc, struct icm_device *dev)
{
	struct icm_get_route *msg;
	struct icm_command *cmd;
	int error;

	tb_debug(icmsc, DBG_TB, "Sending GET_ROUTE\n");

	if ((error = icm_alloc_cmd(icmsc, &cmd)) != 0) {
		tb_printf(icmsc, "Cannot allocate cmd/resp for APPROVE_PCI\n");
		return (error);
	}

	msg = icm_get_frame_data(cmd);
	bzero(msg, sizeof(*msg));
	msg->hdr.cmd = ICM_CMD_GET_ROUTE;
	msg->link_depth = (dev->ld.link << ICM_GETROUTE_LINK_SHIFT) |
	    (dev->ld.depth << ICM_GETROUTE_DEPTH_SHIFT);

	cmd->callback = icm_get_devroute_cb;
	cmd->callback_arg = dev;
	cmd->resp_code = ICM_RESP_GET_ROUTE;

	icm_prepare_cmd(icmsc, cmd, sizeof(*msg), ICM_GET_ROUTE_RESP_LEN);

	if ((error = icm_tx_schedule(icmsc, cmd)) != 0)
		tb_debug(icmsc, DBG_TB, "Error %d sending GET_ROUTE\n",
		    error);

	return (error);
}

/*
 * Completion for the GET_ROUTE request.  Since this request is only
 * for AR devices, it's ok to assume that we'll use the AR version of
 * the APPROVE_DEVICE request at the end of this function.
 */
static void
icm_get_devroute_cb(struct icm_softc *icmsc, struct icm_command *cmd,
    void *arg)
{
	struct icm_get_route_resp *resp;
	struct icm_device *dev;

	KASSERT(arg != NULL, ("Invalid device in icm_get_devroute_cb"));
	dev = (struct icm_device *)arg;
	resp = (struct icm_get_route_resp *)cmd->resp_buffer;

	tb_debug(icmsc, DBG_TB, "GET_ROUTE response received for %d %d\n",
	    dev->ld.link, dev->ld.depth);

	if (resp->hdr.flags & ICM_GETROUTE_ERROR) {
		tb_debug(icmsc, DBG_TB, "GET_ROUTE returned error\n");
	} else {
		dev->route.hi = resp->route.hi;
		dev->route.lo = resp->route.lo;
	}

	icm_free_cmd(icmsc, cmd);

	/* Now that we have the route, finish set-up */
	icm_device_create_sysctls(icmsc, dev);

	/* XXX This should really be moved into a state machine */
	if (((dev->flags & TBDEV_NO_APPROVE) == 0) &&
	    (icmsc->user_approve != 0))
		icm_approve_device_v1(icmsc, dev);

	return;
}

/*
 * Put the message into correct byte order, set the CRC, and set up a few
 * other fields.
 * 'len' is the length of the message in bytes with the CRC
 */
static void
icm_prepare_cmd(struct icm_softc *icmsc, struct icm_command *icmd, int len,
    int resp_len)
{
	struct nhi_cmd_frame *nhicmd;
	uint32_t *msg;
	int i, msglen;

	KASSERT(icmd != NULL, ("cmd cannot be NULL\n"));
	KASSERT(len != 0, ("Invalid zero-length command\n"));

	nhicmd = icmd->nhicmd;
	msglen = (len - 4) / 4;
	for (i = 0; i < msglen; i++)
		nhicmd->data[i] = htobe32(nhicmd->data[i]);

	/* Tack on the CRC */
	msg = (uint32_t *)nhicmd->data;
	msg[msglen] = htobe32(tb_calc_crc(nhicmd->data, len));

	nhicmd->pdf = PDF_CM_REQ;
	nhicmd->req_len = len;

	nhicmd->timeout = NHI_CMD_TIMEOUT;
	nhicmd->retries = 0;
	nhicmd->resp_buffer = (uint32_t *)icmd->resp_buffer;
	nhicmd->resp_len = resp_len;
	nhicmd->context = icmd;
}

/*
 * Only 1 command can be in flight to the CM firmware.  This function
 * both schedules new commands and processes the deferred queue.
 */
static int
icm_tx_schedule(struct icm_softc *icmsc, struct icm_command *icmd)
{
	struct nhi_cmd_frame *nhicmd;
	int error;

	tb_debug(icmsc, DBG_TB, "icm_tx_schedule\n");

	if (icmd != NULL)
		TAILQ_INSERT_TAIL(&icmsc->tx_queue, icmd->nhicmd, cm_link);

	while ((icmsc->tx_inflight_cmd == NULL) &&
	    ((nhicmd = TAILQ_FIRST(&icmsc->tx_queue)) != NULL)) {

		TAILQ_REMOVE(&icmsc->tx_queue, nhicmd, cm_link);
		tb_debug(icmsc, DBG_TB, "Scheduling command with index %d\n",
		    nhicmd->idx);
		icmsc->tx_inflight_cmd = nhicmd;
		if ((error = nhi_tx_schedule(icmsc->ring0, nhicmd)) != 0) {
			icmsc->tx_inflight_cmd = NULL;
			if (error == EBUSY) {
				TAILQ_INSERT_HEAD(&icmsc->tx_queue, nhicmd,
				    cm_link);
				error = 0;
			}
			break;
		}
	}

	return (error);
}

static void
icm_tx_schedule_wakeup(struct icm_softc *icmsc, struct icm_command *icmd,
    void *arg)
{

	mtx_lock(&icmsc->mtx);
	icmd->flags |= ICM_CMD_POLL_COMPLETE;
	mtx_unlock(&icmsc->mtx);
}

static int
icm_tx_schedule_polled(struct icm_softc *icmsc, struct icm_command *icmd)
{
	int retries, timeout, error;

	icmd->callback = icm_tx_schedule_wakeup;
	icmd->callback_arg = NULL;
	retries = ICM_DEFAULT_RETRIES;
	timeout = ICM_DEFAULT_TIMEOUT * 1000000;

	mtx_lock(&icmsc->mtx);
	while (retries-- >= 0) {
		error = icm_tx_schedule(icmsc, icmd);
		if (error)
			break;

		mtx_unlock(&icmsc->mtx);
		while (timeout > 0) {
			DELAY(100 * 1000);
			if ((icmd->flags & ICM_CMD_POLL_COMPLETE) != 0)
				break;
			timeout -= 100000;
		}

		mtx_lock(&icmsc->mtx);
		if ((icmd->flags & ICM_CMD_POLL_COMPLETE) == 0) {
			error = ETIMEDOUT;
			icmsc->tx_inflight_cmd = NULL;
			tb_debug(icmsc, DBG_TB,
			    "ICM command timed out, retries=%d\n", retries);
			continue;
		} else
			break;
	}
	mtx_unlock(&icmsc->mtx);

	return (error);
}

static void
icm_command_default_cb(struct icm_softc *icmsc, struct icm_command *cmd,
    void *arg)
{

	tb_debug(icmsc, DBG_TB, "icm_command_default_cb\n");

	icm_free_cmd(icmsc, cmd);
}

static void
icm_command_complete(struct icm_softc *icmsc, void *arg)
{
	icm_callback_t cb;
	struct icm_command *cmd;
	struct icm_response_hdr hdr;

	KASSERT(arg != NULL, ("arg cannot be NULL\n"));

	/* Should we continue processing a mismatch? */
	cmd = (struct icm_command *)arg;
	*(uint32_t *)&hdr = be32toh(cmd->nhicmd->data[0]);
	if (cmd->resp_code != hdr.code) {
		tb_debug(icmsc, DBG_TB, "Warning: Mismatched req/resp\n");
		tb_debug(icmsc, DBG_RXQ|DBG_TB, "resp_code= %d, hdr= %d\n",
		    cmd->resp_code, hdr.code);
	}

	cb = cmd->callback;
	if (cb == NULL)
		cb = icm_command_default_cb;

	cb(icmsc, cmd, cmd->callback_arg);

	/* Kick the queue in case something was deferred. */
	mtx_lock(&icmsc->mtx);
	icm_tx_schedule(icmsc, NULL);
	mtx_unlock(&icmsc->mtx);

	return;
}

static void
icm_tx_done_intr(void *context, union nhi_ring_desc *desc,
    struct nhi_cmd_frame *nhicmd)
{
	struct icm_softc *icmsc;

	KASSERT(context != NULL, ("context cannot be NULL\n"));
	KASSERT(nhicmd != NULL, ("nhicmd cannot be NULL\n"));

	icmsc = (struct icm_softc *)context;
	tb_debug(icmsc, DBG_TB|DBG_TXQ|DBG_FULL, "Firmware tx complete, "
	   "flags= 0x%x\n", nhicmd->flags);

	if (nhicmd->flags & CMD_RESP_COMPLETE) {
		tb_debug(icmsc, DBG_TB, "RESP_COMPLETE set, callback!\n");
		icm_command_complete(icmsc, nhicmd->context);
	}

	return;
}

static void
icm_rx_resp_intr(void *context, union nhi_ring_desc *ring,
    struct nhi_cmd_frame *rxcmd)
{
	struct icm_softc *icmsc;
	struct nhi_cmd_frame *txcmd;
	struct nhi_rx_post_desc *desc;
	u_int len, i;

	icmsc = (struct icm_softc *)context;
	desc = &ring->rxpost;
	tb_debug(icmsc, DBG_TB|DBG_FULL, "Processing firmware RX response\n");

	/*
	 * RX Responses from the firmware should only be happening as a
	 * result of a waiting TX Request from the driver, and there can
	 * only be one Request/Response in-flight at a time.  If there's no
	 * pending request then this response must be spurious.
	 */
	mtx_lock(&icmsc->mtx);
	txcmd = icmsc->tx_inflight_cmd;
	icmsc->tx_inflight_cmd = NULL;
	mtx_unlock(&icmsc->mtx);
	if (txcmd == NULL) {
		tb_debug(icmsc, DBG_TB|DBG_RXQ, "Spurious RX Response\n");
		goto out;
	}

	/*
	 * Copy the frame into the user-supplied buffer, minus the CRC.
	 * XXX CRC never seems to match from the firmware, so avoid it.
	 */
	rmb();
	len = (desc->eof_len & RX_BUFFER_DESC_LEN_MASK) - 4;
	if (len > txcmd->resp_len) {
		len = txcmd->resp_len;
		rxcmd->flags |= CMD_RESP_OVERRUN;
	}
	if (txcmd->resp_buffer != NULL) {
		for (i = 0; i < len / 4; i++)
			txcmd->resp_buffer[i] = be32toh(rxcmd->data[i]);
	}

	/*
	 * Signal that the response is complete.  Anyone waiting is either
	 * polling or sleeping, and shouldn't be holding a lock.  Still need
	 * to hold a lock here to avoid wakeup races.
	 * XXX Should the lock be held across the callback?
	 */
	txcmd->flags |= CMD_RESP_COMPLETE;
	if (txcmd->flags & CMD_REQ_COMPLETE) {
		tb_debug(icmsc, DBG_RXQ|DBG_TXQ|DBG_TB, "Completing txcmd\n");
		icm_command_complete(icmsc, txcmd->context);
	}

out:
	return;
}

static void
icm_rx_notify_intr(void *context, union nhi_ring_desc *ring,
    struct nhi_cmd_frame *nhicmd)
{
	struct icm_softc *icmsc;
	struct icm_event *event;
	struct nhi_rx_post_desc *desc;
	uint32_t crc;
	int len, i;

	icmsc = (struct icm_softc *)context;
	desc = &ring->rxpost;
	tb_debug(icmsc, DBG_TB, "Processing firmware notify event\n");
	len = (desc->eof_len & RX_BUFFER_DESC_LEN_MASK) - 4;

	/* XXX Is CRC checking necessary? */
	crc = tb_calc_crc(nhicmd->data, len);
	if (0 && crc != nhicmd->data[len / 4])
		tb_debug(icmsc, DBG_TB, "Warning: CRC mismatch for event\n");

	tb_debug(icmsc, DBG_TB|DBG_FULL, "Allocating event buffer length %d\n",
	    len);
	event = malloc(sizeof(*event) + len, M_THUNDERBOLT, M_ZERO|M_NOWAIT);
	if (event == NULL) {
		tb_printf(icmsc, "Cannot alloc memory for event\n");
		return;
	}
	for (i = 0; i < len / 4; i++)
		event->buf[i] = be32toh(nhicmd->data[i]);

	tb_debug(icmsc, DBG_TB|DBG_EXTRA, "Enqueue event task\n");
	mtx_lock(&icmsc->mtx);
	TAILQ_INSERT_TAIL(&icmsc->cmevent_list, event, link);
	taskqueue_enqueue(icmsc->taskqueue, &icmsc->cmevent_task);
	mtx_unlock(&icmsc->mtx);

	return;
}

static void
icm_cmevent_task(void *arg, int pending)
{
	TAILQ_HEAD(, icm_event) evq;
	struct icm_notify_hdr hdr;
	struct icm_softc *icmsc;
	struct icm_event *event;

	icmsc = (struct icm_softc *)arg;

	/*
	 * Move the list to a local head so it can be processed without
	 * juggling the lock.
	 */
	TAILQ_INIT(&evq);
	mtx_lock(&icmsc->mtx);
	TAILQ_CONCAT(&evq, &icmsc->cmevent_list, link);
	mtx_unlock(&icmsc->mtx);

	while ((event = TAILQ_FIRST(&evq)) != NULL) {
		TAILQ_REMOVE(&evq, event, link);

		*(uint32_t *)&hdr = event->buf[0];
		tb_debug(icmsc, DBG_TB|DBG_EXTRA, "Processing event "
		    "%s in taskqueue\n", tb_get_string(hdr.code,
		    tb_notify_code));

		switch (hdr.code) {
		case ICM_NOTIFY_DEVCONN:
			if (NHI_IS_AR(icmsc->sc))
				icm_event_devconn_v1(icmsc, event);
			else
				icm_event_devconn_v2(icmsc, event);
			break;
		case ICM_NOTIFY_DISCONN:
			if (NHI_IS_AR(icmsc->sc))
				icm_event_devdisconn_v1(icmsc, event);
			else
				icm_event_devdisconn_v2(icmsc, event);
			break;
		case ICM_NOTIFY_DOMCONN:
			icm_event_domconn(icmsc, event);
			break;
		case ICM_NOTIFY_DOMDISCONN:
			icm_event_domdisconn(icmsc, event);
			break;
		case ICM_NOTIFY_RTD3:
			icm_event_rtd3(icmsc, event);
			break;
		default:
			tb_printf(icmsc, "Unhandled Notify code %#x %s\n",
			    hdr.code, tb_get_string(hdr.code, tb_notify_code));
			free(event, M_THUNDERBOLT);
		}
	}

	return;
}

static int
icm_uid_sysctl(SYSCTL_HANDLER_ARGS)
{
	struct icm_device *dev;
	struct sbuf *sbuf;
	uint8_t *e;
	int error;

	dev = (struct icm_device *)arg1;

	error = sysctl_wire_old_buffer(req, 0);
	if (error != 0)
		return (error);

	e = &dev->EPUID[0];
	sbuf = sbuf_new_for_sysctl(NULL, NULL, 128, req);
	sbuf_printf(sbuf, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
	    "%02x%02x%02x%02x%02x%02x", e[0], e[1], e[2], e[3], e[4], e[5],
	    e[6], e[7], e[8], e[9], e[10], e[11], e[12], e[13], e[14], e[15]);

	error = sbuf_finish(sbuf);
	sbuf_delete(sbuf);

	return (error);
}

static int
icm_route_sysctl(SYSCTL_HANDLER_ARGS)
{
	struct icm_device *dev;
	struct sbuf *sbuf;
	int error;

	dev = (struct icm_device *)arg1;

	error = sysctl_wire_old_buffer(req, 0);
	if (error != 0)
		return (error);

	sbuf = sbuf_new_for_sysctl(NULL, NULL, 128, req);
	sbuf_printf(sbuf, "0x%08x%08x", dev->route.hi, dev->route.lo);

	error = sbuf_finish(sbuf);
	sbuf_delete(sbuf);

	return (error);
}

static int
icm_power_sysctl(SYSCTL_HANDLER_ARGS)
{
	struct icm_device *dev;
	struct sbuf *sbuf;
	int error;

	dev = (struct icm_device *)arg1;

	error = sysctl_wire_old_buffer(req, 0);
	if (error != 0)
		return (error);

	sbuf = sbuf_new_for_sysctl(NULL, NULL, 128, req);
	sbuf_printf(sbuf, "%s", tb_get_string(dev->power, tb_device_power));

	error = sbuf_finish(sbuf);
	sbuf_delete(sbuf);

	return (error);
}

static int
icm_flags_sysctl(SYSCTL_HANDLER_ARGS)
{
	struct icm_device *dev;
	struct sbuf *sbuf;
	int error;

	dev = (struct icm_device *)arg1;

	error = sysctl_wire_old_buffer(req, 0);
	if (error != 0)
		return (error);

	sbuf = sbuf_new_for_sysctl(NULL, NULL, 128, req);
	sbuf_printf(sbuf, "%b", dev->flags,
	    "\20"
	    "\1CERTWIN"
	    "\2LINK_DUAL"
	    "\3DEPTH_FIRST"
	    "\4LANE_20G"
	    "\5NOT_PCIE"
	    "\6NO_APPROVE"
	    "\7REJECTED"
	    "\10ATBOOT");

	error = sbuf_finish(sbuf);
	sbuf_delete(sbuf);

	return (error);
}

static void
icm_event_devconn_v1(struct icm_softc *icmsc, struct icm_event *event)
{
	struct icm_notify_devconn_v1 *dc;
	struct icm_device *dev;
	u_int link, depth;

	dc = (struct icm_notify_devconn_v1 *)event->buf;
	if (dc == NULL)
		return;

	link = (dc->link_depth & ICM_DEVCONN_LINK_MASK) >>
	    ICM_DEVCONN_LINK_SHIFT;
	depth = (dc->link_depth & ICM_DEVCONN_DEPTH_MASK) >>
	    ICM_DEVCONN_DEPTH_SHIFT;

	tb_debug(icmsc, DBG_TB, "New device notification at link %d "
	    "depth %d\n", link, depth);

	/*
	 * Note: link and depth are counted from 1, so there is no
	 * off-by-one-error in this check.
	 */
	if ((link > TB_MAX_LINKS) || (depth > TB_MAX_DEPTH)) {
		tb_debug(icmsc, DBG_TB, "Link/depth out of range\n");
		goto out;
	}

	/* Make sure this isn't an erroneous duplicate */
	TAILQ_FOREACH(dev, &icmsc->icm_devs, link) {
		if ((dev->ld.link == link) &&
		    (dev->ld.depth == depth)) {
			tb_printf(icmsc, "Warning: duplicate device "
			    "entry at link %d depth %d\n", link, depth);
			goto out;
		}
	}

	dev = malloc(sizeof(*dev), M_THUNDERBOLT, M_NOWAIT|M_ZERO);
	if (dev == NULL)
		goto out;

	dev->ld.link = link;
	dev->ld.depth = depth;
	dev->conn_key = dc->conn_key;
	dev->conn_id = dc->conn_id;
	bcopy(dc->EPUID, dev->EPUID, 16);
	dev->power = (dc->hdr.flags & ICM_DEVCONN_POWER_MASK) >>
	    ICM_DEVCONN_POWER_SHIFT;
	dev->security = (dc->hdr.flags & ICM_DEVCONN_SEC_MASK) >>
	    ICM_DEVCONN_SEC_SHIFT;
	strncpy(dev->vendor, &EPNAME_VENDOR_NAME(dc->ep_name), TB_VENDOR_LEN);
	strncpy(dev->model, &EPNAME_MODEL_NAME(dc->ep_name), TB_MODEL_LEN);

	if (dc->hdr.flags & ICM_DEVCONN_LINK_DUAL)
		dev->flags |= TBDEV_LINK_DUAL;
	if (dc->hdr.flags & ICM_DEVCONN_LANE_20G)
		dev->flags |= TBDEV_LANE_20G;
	if (dc->link_depth & ICM_DEVCONN_NO_APPROVE)
		dev->flags |= TBDEV_NO_APPROVE;
	if (dc->link_depth & ICM_DEVCONN_REJECTED)
		dev->flags |= TBDEV_REJECTED;
	if (dc->link_depth & ICM_DEVCONN_ATBOOT)
		dev->flags |= TBDEV_ATBOOT;

	/*
	 * Pre-load the device route.  The real route will be requested
	 * asynchronously.
	 */
	dev->route.hi = 0xffffffff;
	dev->route.lo = 0xffffffff;

	TAILQ_INSERT_TAIL(&icmsc->icm_devs, dev, link);

	icm_get_devroute(icmsc, dev);

out:
	free(event, M_THUNDERBOLT);
	return;
}

/*
 * Handler for the DEVICE_CONNECTED event for TR and ICL devices.
 * The route is supplied instead of the link-depth, so it's ok to jump
 * directly to the APPROVE_DEVICE request at the end.
 */
static void
icm_event_devconn_v2(struct icm_softc *icmsc, struct icm_event *event)
{
	struct icm_notify_devconn_v2 *dc;
	struct icm_device *dev;
	tb_route_t route;

	dc = (struct icm_notify_devconn_v2 *)event->buf;
	if (dc == NULL)
		return;

	route.hi = dc->route.hi;
	route.lo = dc->route.lo;

	tb_debug(icmsc, DBG_TB, "New device notification at %08x%08x\n",
	    route.hi, route.lo);

	if ((route.hi == 0xffffffff) && (route.lo > 0xffffffff)) {
		tb_debug(icmsc, DBG_TB, "Route out of range\n");
		goto out;
	}

	/* Make sure this isn't an erroneous duplicate */
	TAILQ_FOREACH(dev, &icmsc->icm_devs, link) {
		if ((dev->route.hi == route.hi) &&
		    (dev->route.lo == route.lo)) {
			tb_printf(icmsc, "Warning: duplicate device "
			    "entry at %08x%08x\n", route.hi, route.lo);
			goto out;
		}
	}

	dev = malloc(sizeof(*dev), M_THUNDERBOLT, M_NOWAIT|M_ZERO);
	if (dev == NULL)
		goto out;

	dev->ld.link = -1;
	dev->ld.depth = -1;
	dev->route.hi = route.hi;
	dev->route.lo = route.lo;
	dev->conn_key = -1;
	dev->conn_id = dc->conn_id;
	bcopy(dc->EPUID, dev->EPUID, 16);
	dev->power = (dc->hdr.flags & ICM_DEVCONN_POWER_MASK) >>
	    ICM_DEVCONN_POWER_SHIFT;
	dev->security = (dc->hdr.flags & ICM_DEVCONN_SEC_MASK) >>
	    ICM_DEVCONN_SEC_SHIFT;
	strncpy(dev->vendor, &EPNAME_VENDOR_NAME(dc->ep_name), TB_VENDOR_LEN);
	strncpy(dev->model, &EPNAME_MODEL_NAME(dc->ep_name), TB_MODEL_LEN);

	if (dc->hdr.flags & ICM_DEVCONN_LINK_DUAL)
		dev->flags |= TBDEV_LINK_DUAL;
	if (dc->hdr.flags & ICM_DEVCONN_LANE_20G)
		dev->flags |= TBDEV_LANE_20G;
	if (dc->devflags & ICM_DEVCONN_NO_APPROVE)
		dev->flags |= TBDEV_NO_APPROVE;
	if (dc->devflags & ICM_DEVCONN_REJECTED)
		dev->flags |= TBDEV_REJECTED;
	if (dc->devflags & ICM_DEVCONN_ATBOOT)
		dev->flags |= TBDEV_ATBOOT;

	TAILQ_INSERT_TAIL(&icmsc->icm_devs, dev, link);
	icm_device_create_sysctls(icmsc, dev);

	/* XXX This should be turned into a state machine. */
	if (((dev->flags & TBDEV_NO_APPROVE) == 0) &&
	    (icmsc->user_approve != 0))
		icm_approve_device_v2(icmsc, dev);

out:
	free(event, M_THUNDERBOLT);
	return;
}

static int
icm_device_create_sysctls(struct icm_softc *icmsc, struct icm_device *dev)
{
	struct sysctl_ctx_list *ctx;

	/* XXX Need to defer this to after the route retrieval */
	snprintf(dev->nodename, TB_NODENAME_LEN, "%08x%08x", dev->route.hi,
	    dev->route.lo);
	sysctl_ctx_init(&dev->ctx);
	dev->tree = SYSCTL_ADD_NODE(&dev->ctx,
	    SYSCTL_CHILDREN(icmsc->sysctl_tree),
	    OID_AUTO, dev->nodename, CTLFLAG_RD, 0, "");
	if (dev->tree == NULL) {
		tb_debug(icmsc, DBG_TB, "Failed to create sysctl "
		    "context for device\n");
		return (EINVAL);
	}

	ctx = &dev->ctx;
	SYSCTL_ADD_S8(ctx, SYSCTL_CHILDREN(dev->tree), OID_AUTO,
	    "link", CTLFLAG_RD, &dev->ld.link, 0, "Link");
	SYSCTL_ADD_S8(ctx, SYSCTL_CHILDREN(dev->tree), OID_AUTO,
	    "depth", CTLFLAG_RD, &dev->ld.depth, 0, "Depth");
	SYSCTL_ADD_S8(ctx, SYSCTL_CHILDREN(dev->tree), OID_AUTO,
	    "conn_key", CTLFLAG_RD, &dev->conn_key, 0, "Connection Key");
	SYSCTL_ADD_U8(ctx, SYSCTL_CHILDREN(dev->tree), OID_AUTO,
	    "conn_id", CTLFLAG_RD, &dev->conn_id, 0, "Connection ID");
	SYSCTL_ADD_STRING(ctx, SYSCTL_CHILDREN(dev->tree), OID_AUTO,
	    "vendor", CTLFLAG_RD, dev->vendor, 0, "Vendor Name");
	SYSCTL_ADD_STRING(ctx, SYSCTL_CHILDREN(dev->tree), OID_AUTO,
	    "model", CTLFLAG_RD, dev->model, 0, "Model Name");
	SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(dev->tree), OID_AUTO,
	    "UID", CTLTYPE_STRING|CTLFLAG_RD|CTLFLAG_MPSAFE,
	    dev, 0, icm_uid_sysctl, "A", "UID");
	SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(dev->tree), OID_AUTO,
	    "route", CTLTYPE_STRING|CTLFLAG_RD|CTLFLAG_MPSAFE,
	    dev, 0, icm_route_sysctl, "A", "Route string");
	SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(dev->tree), OID_AUTO,
	    "power", CTLTYPE_STRING|CTLFLAG_RD|CTLFLAG_MPSAFE,
	    dev, 0, icm_power_sysctl, "A", "Power Mode");
	SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(dev->tree), OID_AUTO,
	    "flags", CTLTYPE_STRING|CTLFLAG_RD|CTLFLAG_MPSAFE,
	    dev, 0, icm_flags_sysctl, "A", "Flags");

	return (0);
}

static void
icm_event_devdisconn_v1(struct icm_softc *icmsc, struct icm_event *event)
{
	struct icm_notify_disconn_v1 *dc;
	struct icm_device *dev;
	int link, depth;

	dc = (struct icm_notify_disconn_v1 *)event->buf;
	if (dc == NULL)
		return;

	link = (dc->link_depth & ICM_DISCONN_LINK_MASK) >>
	    ICM_DISCONN_LINK_SHIFT;
	depth = (dc->link_depth & ICM_DISCONN_DEPTH_MASK) >>
	    ICM_DISCONN_DEPTH_SHIFT;

	tb_debug(icmsc, DBG_TB, "Device disconnect notification at "
	    "link %d depth %d\n", link, depth);

	if ((link > TB_MAX_LINKS) || (depth > TB_MAX_DEPTH)) {
		tb_debug(icmsc, DBG_TB, "Link/depth out of range\n");
		goto out;
	}

	TAILQ_FOREACH(dev, &icmsc->icm_devs, link) {
		if ((dev->ld.link == link) && (dev->ld.depth == depth)) {
			icm_free_device(icmsc, dev);
			break;
		}
	}
	if (dev == NULL)
		tb_debug(icmsc, DBG_TB, "Device entry already cleared\n");

out:
	free(event, M_THUNDERBOLT);
	return;
}

static void
icm_event_devdisconn_v2(struct icm_softc *icmsc, struct icm_event *event)
{
	struct icm_notify_disconn_v2 *dc;
	struct icm_device *dev;
	tb_route_t route;

	dc = (struct icm_notify_disconn_v2 *)event->buf;
	if (dc == NULL)
		return;

	route.hi = dc->route.hi;
	route.lo = dc->route.lo;

	tb_debug(icmsc, DBG_TB, "Device disconnect notification at "
	    "route %08x%08x\n", route.hi, route.lo);

	if ((route.hi == 0xffffffff) && (route.lo > 0xffffffff)) {
		tb_debug(icmsc, DBG_TB, "Route out of range\n");
		goto out;
	}

	TAILQ_FOREACH(dev, &icmsc->icm_devs, link) {
		if ((dev->route.hi == route.hi) &&
		    (dev->route.lo == route.lo)) {
			icm_free_device(icmsc, dev);
			break;
		}
	}
	if (dev == NULL)
		tb_debug(icmsc, DBG_TB, "Device entry already cleared\n");

out:
	free(event, M_THUNDERBOLT);
	return;
}

static void
icm_event_domconn(struct icm_softc *icmsc, struct icm_event *event)
{
	struct icm_notify_domain_conn *dc;
	uint8_t *u;

	dc = (struct icm_notify_domain_conn *)event->buf;

	tb_debug(icmsc, DBG_TB, "Domain Connect Event\n");
	tb_debug(icmsc, DBG_TB, "link=%d depth= %d\n",
	    dc->link_depth & ICM_DOMCONN_LINK_MASK,
	    ((dc->link_depth & ICM_DOMCONN_DEPTH_MASK)
	    >> ICM_DOMCONN_DEPTH_SHIFT));
	tb_debug(icmsc, DBG_TB, "flags= 0x%x\n", dc->link_depth);
	u = dc->remote_uid;
	tb_debug(icmsc, DBG_TB, "Remote UUID=%02x%02x%02x%02x-%02x%02x-"
	    "%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n", u[0], u[1], u[2],
	    u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12],
	    u[13], u[14], u[15]);
	u = dc->local_uid;
	tb_debug(icmsc, DBG_TB, "Local UUID=%02x%02x%02x%02x-%02x%02x-"
	    "%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n", u[0], u[1], u[2],
	    u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12],
	    u[13], u[14], u[15]);
	tb_debug(icmsc, DBG_TB, "Local Route= 0x%08x%08x\n",
	    dc->local_route.hi, dc->local_route.lo);
	tb_debug(icmsc, DBG_TB, "Remote Route= 0x%08x%08x\n",
	    dc->remote_route.hi, dc->remote_route.lo);
	free(event, M_THUNDERBOLT);
	return;
}

static void
icm_event_domdisconn(struct icm_softc *icmsc, struct icm_event *event)
{

	tb_debug(icmsc, DBG_TB, "Domain Disconnect Event\n");

	free(event, M_THUNDERBOLT);
	return;
}

static void
icm_event_rtd3(struct icm_softc *icmsc, struct icm_event *event)
{
	struct icm_notify_rtd3 *r;

	r = (struct icm_notify_rtd3 *)event;

	tb_debug(icmsc, DBG_TB, "RTD3 Veto, reason= 0x%x\n", r->reason);

	free(event, M_THUNDERBOLT);
	return;
}

int
icm_get_uuid(struct nhi_softc *nsc)
{
	struct icm_softc *icmsc;
	struct icm_preboot_acl *msg;
	struct icm_preboot_acl_resp *resp;
	struct icm_command *cmd;
	int error, i;

	icmsc = nsc->icmsc;
	tb_debug(icmsc, DBG_TB, "Sending PREBOOT_ACL\n");

	if ((error = icm_alloc_cmd(icmsc, &cmd)) != 0) {
		tb_printf(icmsc, "Cannot allocate cmd/resp for PREBOOT_ACL\n");
		return (ENOMEM);
	}

	msg = icm_get_frame_data(cmd);
	bzero(msg, sizeof(*msg));
	msg->hdr.cmd = ICM_CMD_PREBOOT_ACL;
	cmd->resp_code = ICM_RESP_PREBOOT_ACL;
	icm_prepare_cmd(icmsc, cmd, sizeof(*msg), NHI_RING0_FRAME_SIZE);

	error = icm_tx_schedule_polled(icmsc, cmd);
	if (error == EWOULDBLOCK) {
		tb_printf(icmsc, "ERROR: Timeout sending DRIVER_READY\n");
	} else if (error == EBUSY) {
		tb_printf(icmsc, "ERROR: No queue space for DRIVER_READY\n");
	} else if (error != 0) {
		tb_printf(icmsc, "Error %d sending DRIVER_READY\n", error);
	}

	if (error)
		return (error);

	resp = (struct icm_preboot_acl_resp *)cmd->resp_buffer;

	if (resp->hdr.flags & ICM_DRVREADY_ERROR)
		tb_printf(icmsc, "Error in PREBOOT_ACL response flags, 0x%02x\n", resp->hdr.flags);

	for (i = 0; i < ICM_PREBOOT_ACL_ENTRIES; i++)
		tb_printf(icmsc, "ACL[%i]: 0x%08x%08x\n", i, resp->acl_entry[i].hi, resp->acl_entry[i].lo);

	icm_free_cmd(icmsc, cmd);
	return (0);
}
