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
 * Thunderbolt Variables
 *
 * $FreeBSD$
 */

#ifndef _TB_REG_H
#define _TB_REG_H

#define TBSEC_NONE	0x00
#define TBSEC_USER	0x01
#define TBSEC_SECURE	0x02
#define TBSEC_DP	0x03
#define TBSEC_UNKNOWN	0xff

/*
 * SW-FW commands and responses.  These are sent over Ring0 to communicate
 * with the fabric and the TBT Connection Manager firmware.
 */

typedef struct {
	uint32_t	hi;
	uint32_t	lo;
} __packed tb_route_t;

struct icm_request_hdr {
	uint8_t		cmd;
	uint8_t		flags;
	uint16_t	hdr_reserved;
} __packed;

struct icm_response_hdr {
	uint8_t		code;
	uint8_t		flags;
	uint8_t		packet_id;
	uint8_t		total_packets;
} __packed;

struct icm_notify_hdr {
	uint8_t		code;
	uint8_t		flags;
	uint8_t		packet_id;
	uint8_t		total_packets;
} __packed;

/* Request: Driver Ready (0x03) */
struct icm_driver_ready {
	struct icm_request_hdr	hdr;
#define ICM_CMD_DRIVER_READY		0x03
#define ICM_CMD_DRIVER_READY_LEN	4
	uint32_t		crc;
} __packed;

/* Response: Driver Ready (0x03) */
struct icm_driver_ready_resp_v1 {
	struct icm_response_hdr		hdr;
#define ICM_RESP_DRIVER_READY		0x03
#define ICM_DRVREADY_ERROR		(1 << 0)
#define ICM_DRVREADY_CERT_TB_1ST_DEPTH	(0x000 << 1)
#define ICM_DRVREADY_ANY_TB_1ST_DEPTH	(0x001 << 1)
#define ICM_DRVREADY_CERT_TB_ANY_DEPTH	(0x100 << 1)
#define ICM_DRVREADY_ANY_TB_ANY_DEPTH	(0x101 << 1)
#define ICM_DRVREADY_CONNMODE_MASK	(0x111 << 1)
#define ICM_DRVREADY_DP_TUNNEL_MODE	(1 << 4)
#define ICM_DRVREADY_EXGPU		(1 << 5)
#define ICM_DRVREADY_RTD3		(1 << 6)
#define ICM_DRVREADY_PCIE		(1 << 7)
	uint8_t				rom_version;
	uint8_t				ram_version;
	uint16_t			security_level;
#define ICM_DRVREADY_SECURITY_MASK	GENMASK(3, 0)
#define ICM_DRVREADY_ACL_SHIFT		7
#define ICM_DRVREADY_ACL_MASK		GENMASK(11, 7)
#define ICM_DRVREADY_ACL_SUPPORTED	(1 << 13)
#define ICM_DRVREADY_ACL_MAX		16
	uint32_t			crc;
} __packed;

struct icm_driver_ready_resp_v2 {
	struct icm_response_hdr		hdr;
	uint8_t				rom_version;
	uint8_t				ram_version;
	uint16_t			security_level;
#define ICM_DRVREADY_V2_SECURITY_MASK	GENMASK(2, 0)
#define ICM_DRVREADY_V2_ACL_SHIFT	7
#define ICM_DRVREADY_V2_ACL_MASK	GENMASK(12, 7)
	uint32_t			nvm_version;
	uint16_t			pci_dev_id;
	uint16_t			reserved1;
	uint32_t			crc;
} __packed;

/* Request: Approve Device (0x04) */
struct icm_approve_pci_v1 {
	struct icm_request_hdr		hdr;
#define ICM_CMD_APPROVE_PCI		0x04
	uint8_t				EPUID[16];	/* Endpoint Unique ID */
	uint8_t				conn_key;
	uint8_t				conn_id;
	uint16_t			reserved;
	uint32_t			crc;
} __packed;

struct icm_approve_pci_v2 {
	struct icm_request_hdr		hdr;
	uint8_t				EPUID[16];	/* Endpoint Unique ID */
	tb_route_t			route;
	uint8_t				conn_id;
	uint8_t				reserved1[3];
	uint32_t			crc;
} __packed;

/* Response: Approve Device (0x04) */
struct icm_approve_pci_resp_v1 {
	struct icm_response_hdr		hdr;
#define ICM_RESP_APPROVE_PCI		0x04
#define ICM_APPROVEPCI_ERROR		(1 << 0)
#define ICM_APPROVEPCI_EXGPU_NOT_CONN	(1 << 1)
	uint8_t				EPUID[16];
	uint8_t				conn_key;
	uint8_t				conn_id;
	uint16_t			reserved;
	uint32_t			crc;
} __packed;
#define ICM_APPROVE_PCI_RESP_1_LEN	(sizeof(struct icm_approve_pci_resp_v1))

struct icm_approve_pci_resp_v2 {
	struct icm_response_hdr		hdr;
	uint8_t				EPUID[16];
	tb_route_t			route;
	uint8_t				conn_id;
	uint8_t				reserved1[3];
	uint32_t			crc;
} __packed;
#define ICM_APPROVE_PCI_RESP_2_LEN	(sizeof(struct icm_approve_pci_resp_v2))

/* Request: Challenge Device (0x05) */
struct icm_challenge_pci {
	struct icm_request_hdr		hdr;
#define ICM_CMD_CHALLENGE_PCI		0x05
	uint8_t				EPUID[16];
	uint8_t				conn_key;
	uint8_t				conn_id;
	uint16_t			reserved;
	uint8_t				challenge[32];
	uint32_t			crc;
} __packed;

/* Response: Challenge Device (0x05) */
struct icm_challenge_pci_resp {
	struct icm_response_hdr		hdr;
#define ICM_RESP_CHALLENGE_PCI		0x05
#define ICM_CHLNGPCI_ERROR		(1 << 0)
#define ICM_CHLNGPCI_NOKEY		(1 << 1)
	uint8_t				EPUID[16];
	uint8_t				conn_key;
	uint8_t				conn_id;
	uint16_t			reserved;
	uint8_t				challenge[32];
	uint8_t				response[32];
	uint32_t			crc;
} __packed;

/* Request: Add Device Key (0x06) */
struct icm_add_device_key {
	struct icm_request_hdr		hdr;
#define ICM_CMD_ADD_DEVICE_KEY		0x06
	uint8_t				EPUID[16];
	uint8_t				conn_key;
	uint8_t				conn_id;
	uint16_t			reserved;
	uint8_t				key[32];
	uint32_t			crc;
} __packed;

/* Response: Add Device Key (0x06) */
struct icm_add_device_key_resp {
	struct icm_response_hdr		hdr;
#define ICM_RESP_ADD_DEVICE_KEY		0x06
#define ICM_ADDDEVKEY_ERROR		(1 << 0)
	uint8_t				EPUID[16];
	uint8_t				conn_key;
	uint8_t				conn_id;
	uint16_t			reserved;
	uint32_t			crc;
} __packed;

/* Request: Get Route (0x0a) */
struct icm_get_route {
	struct icm_request_hdr		hdr;
#define ICM_CMD_GET_ROUTE		0x0a
	uint16_t			reserved0;
	uint16_t			link_depth;
#define ICM_GETROUTE_LINK_MASK		0x7
#define ICM_GETROUTE_LINK_SHIFT		0
#define ICM_GETROUTE_DEPTH_SHIFT	4
	uint32_t			crc;
} __packed;

/* Response: Get Route (0x0a) */
struct icm_get_route_resp {
	struct icm_response_hdr		hdr;
#define ICM_RESP_GET_ROUTE		0x0a
#define ICM_GETROUTE_ERROR		(1 << 0)
	uint16_t			reserved0;
	uint16_t			link_depth;
	tb_route_t			route;
	uint32_t			crc;
} __packed;
#define ICM_GET_ROUTE_RESP_LEN	(sizeof(struct icm_get_route_resp))

/* Request: Approve Domain (0x10) */
struct icm_approve_domain {
	struct icm_request_hdr		hdr;
#define ICM_CMD_APPROVE_DOMAIN		0x10
	uint16_t			reserved0;
	uint8_t				link_depth;
#define ICM_APPROVEDOM_LINK_MASK	0x07
#define ICM_APPROVEDOM_DEPTH_SHIFT	4
	uint8_t				reserved1;
	uint8_t				DMUID[16];
	uint16_t			txhopid;
	uint16_t			thopid;
	uint16_t			rxhopid;
	uint16_t			rhopid;
	uint32_t			crc;
} __packed;

/* Response: Approve Domain (0x10) */
struct icm_approve_domain_resp {
	struct icm_response_hdr		hdr;
#define ICM_RESP_APPROVE_DOMAIN		0x10
#define ICM_APPROVEDOM_ERROR		(1 << 0)
	uint16_t			reserved0;
	uint8_t				link_depth;
	uint8_t				reserved1;
	uint8_t				DMUID[16];
	uint16_t			txhopid;
	uint16_t			thopid;
	uint16_t			rxhopid;
	uint16_t			rhopid;
	uint32_t			crc;
} __packed;

/* Request: Disconnect Domain (x011) */
#define ICM_CMD_DISCONN_DOMAIN		0x11

/* Response: Disconnect Domain (0x11) */
#define ICM_RESP_DISCONN_DOMAIN		0x11

/* Request: Preboot ACL (0x18) */
#define ICM_PREBOOT_ACL_ENTRIES		16
struct icm_preboot_acl {
	struct icm_request_hdr		hdr;
#define ICM_CMD_PREBOOT_ACL		0x10
	struct {
		uint32_t	lo;
		uint32_t	hi;
	} acl_entry[ICM_PREBOOT_ACL_ENTRIES];
	uint32_t			crc;
} __packed;

struct icm_preboot_acl_resp {
	struct icm_response_hdr		hdr;
#define ICM_RESP_PREBOOT_ACL		0x18
	struct {
		uint32_t	lo;
		uint32_t	hi;
	} acl_entry[ICM_PREBOOT_ACL_ENTRIES];
	uint32_t			crc;
} __packed;

/* Event: Device Connected (0x03) */
/* Device Connected notification.  Alpine Ridge */
struct icm_notify_devconn_v1 {
	struct icm_notify_hdr		hdr;
#define ICM_NOTIFY_DEVCONN		0x03
#define ICM_DEVCONN_POWER_SELF		(0x0 << 1)
#define ICM_DEVCONN_POWER_NORM		(0x1 << 1)
#define ICM_DEVCONN_POWER_HIGH		(0x2 << 1)
#define ICM_DEVCONN_POWER_UNK		(0x3 << 1)
#define ICM_DEVCONN_POWER_MASK		(0x7 << 1)
#define ICM_DEVCONN_POWER_SHIFT		1
#define ICM_DEVCONN_SEC_MASK		0xc
#define ICM_DEVCONN_SEC_SHIFT		3
#define ICM_DEVCONN_LINK_DUAL		(1 << 5)
#define ICM_DEVCONN_LANE_20G		(1 << 7)
	uint8_t				EPUID[16];
	uint8_t				conn_key;
	uint8_t				conn_id;
	uint16_t			link_depth;
#define ICM_DEVCONN_LINK_MASK		0x7
#define ICM_DEVCONN_LINK_SHIFT		0
#define ICM_DEVCONN_DEPTH_MASK		0xf0
#define ICM_DEVCONN_DEPTH_SHIFT		4
#define ICM_DEVCONN_NO_APPROVE		(1 << 8) /* Approval not needed */
#define ICM_DEVCONN_REJECTED		(1 << 9)
#define ICM_DEVCONN_ATBOOT		(1 << 10)
#define ICM_DEVCONN_SKL			(0x001 << 11)
#define ICM_DEVCONN_REJECT_REASON	(0x11 << 14)
	uint8_t				ep_name[220];
	uint32_t			crc;
} __packed;

#define EPNAME_VENDOR_LEN(epname)	(epname)[0]
#define EPNAME_VENDOR_STRUCT(epname)	(epname)[1]
#define EPNAME_VENDOR_NAME(epname)	(epname)[2]
#define EPNAME_MODEL_LEN(epname)	(epname)[EPNAME_VENDOR_LEN(epname)]
#define EPNAME_MODEL_STRUCT(epname)	(epname)[EPNAME_VENDOR_LEN(epname) + 1]
#define EPNAME_MODEL_NAME(epname)	(epname)[EPNAME_VENDOR_LEN(epname) + 2]

#define EPNAME_STRUCT_VENDOR			0x01
#define EPNAME_STRUCT_MODEL			0x02

/* Device Connected notification.  Icelake */
struct icm_notify_devconn_v2 {
	struct icm_notify_hdr		hdr;
	uint8_t				EPUID[16];
	tb_route_t			route;
	uint8_t				conn_id;
	uint8_t				rsrvd1;
	uint16_t			devflags; /* Uses link_depth flags */
	uint8_t				ep_name[220];
	uint32_t			crc;
} __packed;

/* Event: Device Disconnected (0x04) */
struct icm_notify_disconn_v1 {
	struct icm_notify_hdr		hdr;
#define ICM_NOTIFY_DISCONN		0x04
	uint16_t			reserved0;
	uint8_t				link_depth;
#define ICM_DISCONN_LINK_MASK		0x07
#define ICM_DISCONN_LINK_SHIFT		0
#define ICM_DISCONN_DEPTH_SHIFT		4
#define ICM_DISCONN_DEPTH_MASK		0xf0
	uint8_t				reserved1;
	uint32_t			crc;
} __packed;

struct icm_notify_disconn_v2 {
	struct icm_notify_hdr		hdr;
	tb_route_t			route;
	uint32_t			crc;
} __packed;

/* Event: DisplayPort Connected (0x05) */
struct icm_notify_dpconn {
	struct icm_notify_hdr		hdr;
#define ICM_NOTIFY_DPCONN		0x05
	uint32_t			crc;
} __packed;

/* Event: Domain Connected (0x06) */
struct icm_notify_domain_conn {
	struct icm_notify_hdr		hdr;
#define ICM_NOTIFY_DOMCONN		0x06
	uint16_t			reserved0;
	uint8_t				link_depth; /* Only used for AR */
#define ICM_DOMCONN_LINK_MASK		0x07
#define ICM_DOMCONN_LINK_SHIFT		0
#define ICM_DOMCONN_NO_APPROVE		(1 << 3)
#define ICM_DOMCONN_DEPTH_SHIFT		4
#define ICM_DOMCONN_DEPTH_MASK		0xf0
	uint8_t				flags;
#define ICM_DOMCONN_PROP_FW		(1 << 0)
#define ICM_DOMCONN_PROP_CHANGE_FW	(1 << 1)
#define ICM_DOMCONN_LINK_DUAL		(1 << 2)
#define ICM_DOMCONN_LANE_20G		(1 << 3)
	uint8_t				remote_uid[16];
	uint8_t				local_uid[16];
	tb_route_t			local_route;
	tb_route_t			remote_route;
	uint32_t			crc;
} __packed;

/* Event: Domain Disconnected (0x07) */
struct icm_notify_domain_disconn_v1 {
	struct icm_notify_hdr		hdr;
#define ICM_NOTIFY_DOMDISCONN		0x07
	uint16_t			reserved0;
	uint8_t				link_depth;
#define ICM_DOMDISCONN_LINK_MASK	0x07
#define ICM_DOMDISCONN_LINK_SHIFT	0
#define ICM_DOMDISCONN_DEPTH_SHIFT	4
#define ICM_DOMDISCONN_DEPTH_MASK	0xf0
	uint8_t				reserved1;
	uint8_t				remote_uid[16];
	uint32_t			crc;
} __packed;

struct icm_notify_domain_disconn_v2 {
	struct icm_notify_hdr		hdr;
	tb_route_t			route;
	uint8_t				remote_uid[16];
	uint32_t			crc;
} __packed;

/* Event: RTD3 Veto (0x0a) */
struct icm_notify_rtd3 {
	struct icm_notify_hdr		hdr;
#define ICM_NOTIFY_RTD3			0x0a
	uint32_t			reason;
	uint32_t			crc;
} __packed;

#endif /* _TB_REG_H */
