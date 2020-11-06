/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the ND protocol.
 *
 * Version:	@(#)nd.h	1.0.2	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _UAPI_LINUX_ND_H
#define _UAPI_LINUX_ND_H

#include <linux/types.h>

/* include all headers not just ND */
#define ND_HEADER_MAX_SIZE 128 +  MAX_HEADER

#define ND_MAX_MESSAGE_LENGTH 1000000
/**
 * enum nd_packet_type - Defines the possible types of ND packets.
 * 
 * See the xxx_header structs below for more information about each type.
 */
enum nd_packet_type {
	// For Phost
	DATA               = 20,
	TOKEN              = 21,
	NOTIFICATION	   = 22,
	ACK  			   = 23,
	SYNC               = 24,
	SYNC_ACK		   = 25,
	//For PIM
	RTS                = 26,
	GRANT			   = 27,
	ACCEPT			   = 28,

	FIN              = 29,
};

// struct vs_hdr {
// 	/** @type: One of the values of &enum packet_type. */
// 	__u8 type;
// 	/**
// 	 * @doff: High order 4 bits holds the number of 4-byte chunks in a
// 	 * data_header (low-order bits unused). Used only for DATA packets;
// 	 * must be in the same position as the data offset in a TCP header.
// 	 */
// 	__u8 doff;
// 	__be16	source;
// 	__be16	dest;
// 	/**
// 	 * @unused1: corresponds to the sequence number field in TCP headers;
// 	 * must not be used by ND, in case it gets incremented during TCP
// 	 * offload.
// 	 */
// 	__be16 len;
// 	__be32 seq;
// };
// struct vs_sync_hdr {
// 	struct vs_hdr common;
// 	// __be64 flow_id;
// 	// __be32 flow_size;
// 	// __be64 start_time;
// };

struct ndhdr {
	__be16	source;
	__be16	dest;
	/**
	 * @unused1: corresponds to the sequence number field in TCP headers;
	 * must not be used by ND, in case it gets incremented during TCP
	 * offload.
	 */
	__be32 seq;
	
	__be32 segment_length;

	/**
	 * @doff: High order 4 bits holds the number of 4-byte chunks in a
	 * data_header (low-order bits unused). Used only for DATA packets;
	 * must be in the same position as the data offset in a TCP header.
	 */
	__u8 doff;

	/** @type: One of the values of &enum packet_type. */
	__u8 type;

	/**
	 * @gro_count: value on the wire is undefined. Used only by
	 * nd_offload.c (it counts the total number of packets aggregated
	 * into this packet, including the top-level packet). Unused for now
	 */
	__u16 gro_count;
	
	/**
	 * @checksum: not used by Homa, but must occupy the same bytes as
	 * the checksum in a TCP header (TSO may modify this?).*/
	__be16 check;

	__be16 len;
	// *
	//  * @priority: the priority at which the packet was set; used
	//  * only for debugging.
	 
	// __u16 priority;
}__attribute__((packed));

/** 
 * struct data_segment - Wire format for a chunk of data that is part of
 * a DATA packet. A single sk_buff can hold multiple data_segments in order
 * to enable send and receive offload (the idea is to carry many network
 * packets of info in a single traversal of the Linux networking stack).
 * A DATA sk_buff contains a data_header followed by any number of
 * data_segments.
 */
struct data_segment {
	/**
	 * @offset: Offset within message of the first byte of data in
	 * this segment. Segments within an sk_buff are not guaranteed
	 * to be in order.
	 */
	__be32 offset;
	
	/** @segment_length: Number of bytes of data in this segment. */
	__be32 segment_length;
	
	/** @data: the payload of this segment. */
	char data[0];
} __attribute__((packed));

struct nd_data_hdr {
	struct ndhdr common;
	__u8 free_token;
	/* padding*/
	__u8 unused1;
	__u16 unused2;
	// __u8 priority;
	// __be64 message_id;
	/* token seq number */
	// __be32 seq_no;
	// __be32 data_seq_no;
    struct data_segment seg;
} __attribute__((packed));

// _Static_assert(sizeof(struct nd_data_hdr) <= ND_HEADER_MAX_SIZE,
// 		"data_header too large");

// _Static_assert(((sizeof(struct nd_data_hdr) - sizeof(struct data_segment))
// 		& 0x3) == 0,
// 		" data_header length not a multiple of 4 bytes (required "
// 		"for TCP/TSO compatibility");

struct nd_token_hdr {
	struct ndhdr common;
	__be32 rcv_nxt;
	__be32 grant_nxt;
	__u8 priority;
	__u8 num_sacks;
	/* token seq number */
}__attribute__((packed));

// _Static_assert(sizeof(struct nd_token_hdr) <= ND_HEADER_MAX_SIZE,
// 		"token_header too large");

struct nd_flow_sync_hdr {
	struct ndhdr common;
	__be64 flow_id;
	__be32 flow_size;
	__be64 start_time;
};
// _Static_assert(sizeof(struct nd_flow_sync_hdr) <= ND_HEADER_MAX_SIZE,
// 		"flow_sync_header too large");

struct nd_ack_hdr {
	struct ndhdr common;
	__be32 rcv_nxt;
};
// _Static_assert(sizeof(struct nd_ack_hdr) <= ND_HEADER_MAX_SIZE,
// 		"nd_ack_header too large");
struct nd_rts_hdr {
	struct ndhdr common;
	__u8 iter;
	__be64 epoch;
	__be32 remaining_sz;
};

struct nd_grant_hdr {
	struct ndhdr common;
	__u8 iter;
	__be64 epoch;
	__be32 remaining_sz;
	__u8 prompt;
};

struct nd_accept_hdr {
	struct ndhdr common;
	__u8 iter;
	__be64 epoch;
	// __u8 accept;

};

enum {
	SKB_GSO_ND = 1 << 19,
	SKB_GSO_ND_L4 = 1 << 20,
};

#define SOL_VIRTUAL_SOCK 19
// #define SOL_VIRTUAL_SOCKLITE 19

/* ND's protocol number within the IP protocol space (this is not an
 * officially allocated slot).
 */
#define IPPROTO_VIRTUAL_SOCK 19
// #define IPPROTO_VIRTUAL_SOCKLITE 19

/* ND socket options */
#define ND_CORK	1	/* Never send partially complete segments */
#define ND_ENCAP	100	/* Set the socket to accept encapsulated packets */
#define ND_NO_CHECK6_TX 101	/* Disable sending checksum for ND6X */
#define ND_NO_CHECK6_RX 102	/* Disable accpeting checksum for ND6 */
#define ND_SEGMENT	103	/* Set GSO segmentation size */
#define ND_GRO		104	/* This socket can receive ND GRO packets */

/* ND encapsulation types */
#define ND_ENCAP_ESPINND_NON_IKE	1 /* draft-ietf-ipsec-nat-t-ike-00/01 */
#define ND_ENCAP_ESPINND	2 /* draft-ietf-ipsec-nd-encaps-06 */
#define ND_ENCAP_L2TPINND	3 /* rfc2661 */
#define ND_ENCAP_GTP0		4 /* GSM TS 09.60 */
#define ND_ENCAP_GTP1U		5 /* 3GPP TS 29.060 */
#define ND_ENCAP_RXRPC		6
#define TCP_ENCAP_ESPINTCP	7 /* Yikes, this is really xfrm encap types. */

#endif /* _UAPI_LINUX_ND_H */
