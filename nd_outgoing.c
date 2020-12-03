// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		DATACENTER ADMISSION CONTROL PROTOCOL(ND) 
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Alan Cox, <alan@lxorguk.ukuu.org.uk>
 *		Hirokazu Takahashi, <taka@valinux.co.jp>
 */

#define pr_fmt(fmt) "ND: " fmt

#include <linux/uaccess.h>
#include <asm/ioctls.h>
#include <linux/memblock.h>
#include <linux/highmem.h>
#include <linux/swap.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/module.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/igmp.h>
#include <linux/inetdevice.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/mm.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <net/tcp_states.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <net/net_namespace.h>
#include <net/icmp.h>
#include <net/inet_hashtables.h>
#include <net/ip_tunnels.h>
#include <net/route.h>
#include <net/checksum.h>
#include <net/xfrm.h>
#include <trace/events/udp.h>
#include <linux/static_key.h>
#include <trace/events/skb.h>
#include <net/busy_poll.h>
#include "nd_impl.h"
#include <net/sock_reuseport.h>
#include <net/addrconf.h>
#include <net/tcp.h>
#include <net/udp_tunnel.h>

#include "nd_host.h"
// #include "linux_nd.h"
 #include "net_nd.h"
// #include "net_ndlite.h"
#include "uapi_linux_nd.h"
#include "nd_impl.h"


#define ND_DEFERRED_ALL (NDF_TSQ_DEFERRED |		\
			  NDF_CLEAN_TIMER_DEFERRED |	\
			  NDF_TOKEN_TIMER_DEFERRED |	\
			  NDF_RMEM_CHECK_DEFERRED | \
			  NDF_RTX_DEFERRED | \
			  NDF_WAIT_DEFERRED)

/**
 * nd_release_cb - nd release_sock() callback
 * @sk: socket
 *
 * called from release_sock() to perform protocol dependent
 * actions before socket release.
 */
void nd_release_cb(struct sock *sk)
{
	unsigned long flags, nflags;

	/* perform an atomic operation only if at least one flag is set */
	do {
		flags = sk->sk_tsq_flags;
		if (!(flags & ND_DEFERRED_ALL))
			return;
		nflags = flags & ~ND_DEFERRED_ALL;
	} while (cmpxchg(&sk->sk_tsq_flags, flags, nflags) != flags);

	// if (flags & TCPF_TSQ_DEFERRED) {
	// 	tcp_tsq_write(sk);
	// 	__sock_put(sk);
	// }
	/* Here begins the tricky part :
	 * We are called from release_sock() with :
	 * 1) BH disabled
	 * 2) sk_lock.slock spinlock held
	 * 3) socket owned by us (sk->sk_lock.owned == 1)
	 *
	 * But following code is meant to be called from BH handlers,
	 * so we should keep BH disabled, but early release socket ownership
	 */
	sock_release_ownership(sk);

	/* First check read memory */
	// if (flags & NDF_RMEM_CHECK_DEFERRED) {
	// 	nd_rem_check_handler(sk);
	// }

	// if (flags & NDF_CLEAN_TIMER_DEFERRED) {
	// 	nd_clean_rtx_queue(sk);
	// 	// __sock_put(sk);
	// }
	// if (flags & NDF_TOKEN_TIMER_DEFERRED) {
	// 	WARN_ON(true);
	// 	nd_token_timer_defer_handler(sk);
	// 	// __sock_put(sk);
	// }
	// if (flags & NDF_RTX_DEFERRED) {
	// 	WARN_ON(true);
	// 	nd_write_timer_handler(sk);
	// }
	// if (flags & NDF_WAIT_DEFERRED) {
	// 	WARN_ON(true);
	// 	nd_flow_wait_handler(sk);
	// }
	// if (flags & TCPF_MTU_REDUCED_DEFERRED) {
	// 	inet_csk(sk)->icsk_af_ops->mtu_reduced(sk);
	// 	__sock_put(sk);
	// }
}
EXPORT_SYMBOL(nd_release_cb);

int nd_init_request(struct sock* sk, struct nd_conn_request *req)
{
	// struct nd_conn_queue *queue = NULL;
	// if(queue_id == -1) {
	// 	queue = &nd_ctrl->queues[1];
	// } else {
	// 	queue =  &nd_ctrl->queues[queue_id];
	// }
	struct nd_sock *nsk = nd_sk(sk);
	req->hdr = page_frag_alloc(&nsk->pf_cache,
		sizeof(struct ndhdr), GFP_KERNEL | __GFP_ZERO);
	if (!req->hdr){
		pr_warn("WARNING: fail to allocat page \n");
		return -ENOMEM;
	}

	// req->queue = queue;
	return 0;
}

struct sk_buff* __construct_control_skb(struct sock* sk, int size) {

	struct sk_buff *skb;
	if(!size)
		size = ND_HEADER_MAX_SIZE;
	skb = alloc_skb(size, GFP_ATOMIC);
	skb->sk = sk;
	// int extra_bytes;
	if (unlikely(!skb))
		return NULL;
	skb_reserve(skb, ND_HEADER_MAX_SIZE);
	skb_reset_transport_header(skb);

	// h = (struct nd_hdr *) skb_put(skb, length);
	// memcpy(h, contents, length);
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	// ((struct inet_sock *) sk)->tos = TOS_7;
	// skb->priority = sk.sk_priority = 7;
	// dst_hold(peer->dst);
	// skb_dst_set(skb, peer->dst);

	return skb;
}

struct nd_conn_request* construct_sync_req(struct sock* sk) {
	// int extra_bytes = 0;
	struct inet_sock *inet = inet_sk(sk);
	struct nd_conn_request* req = kzalloc(sizeof(*req), GFP_KERNEL);
	struct ndhdr* sync;
	if(unlikely(!req)) {
		WARN_ON(true);
		return NULL;
	}
	nd_init_request(sk, req);
	req->state = ND_CONN_SEND_CMD_PDU;
	sync = req->hdr;
	// req->pdu_len = sizeof(struct ndhdr);
	req->offset = 0;
	req->data_sent = 0;
	// struct sk_buff* skb = __construct_control_skb(sk, 0);
	// struct nd_flow_sync_hdr* fh;
	// struct ndhdr* dh; 

	// fh = (struct nd_flow_sync_hdr *) skb_put(skb, sizeof(struct nd_flow_sync_hdr));
	
	// dh = (struct ndhdr*) (&sync->common);
	sync->len = 0;
	sync->type = SYNC;
	sync->source = inet->inet_sport;
	sync->dest = inet->inet_dport;
	// sync->check = 0;
	sync->doff = (sizeof(struct ndhdr)) << 2;

	// fh->flow_id = message_id;
	// fh->flow_size = htonl(message_size);
	// fh->start_time = start_time;
	// extra_bytes = ND_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return req;
}

struct nd_conn_request* construct_sync_ack_req(struct sock* sk) {
	// int extra_bytes = 0;
	struct inet_sock *inet = inet_sk(sk);
	struct nd_conn_request* req = kzalloc(sizeof(*req), GFP_KERNEL);
	struct ndhdr* sync;

	// struct sk_buff* skb = __construct_control_skb(sk, 0);
	// struct nd_flow_sync_hdr* fh;
	// struct ndhdr* dh; 
	if(unlikely(!req)) {
		return NULL;
	}
	nd_init_request(sk, req);
	req->state = ND_CONN_SEND_CMD_PDU;
	sync = req->hdr;
	// req->pdu_len = sizeof(struct ndhdr);

	// fh = (struct nd_flow_sync_hdr *) skb_put(skb, sizeof(struct nd_flow_sync_hdr));
	
	// dh = (struct ndhdr*) (&sync->common);
	sync->len = 0;
	sync->type = SYNC_ACK;
	sync->source = inet->inet_sport;
	sync->dest = inet->inet_dport;
	// sync->check = 0;
	sync->doff = (sizeof(struct ndhdr)) << 2;

	// fh->flow_id = message_id;
	// fh->flow_size = htonl(message_size);
	// fh->start_time = start_time;
	// extra_bytes = ND_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return req;
}

struct nd_conn_request* construct_ack_req(struct sock* sk, gfp_t flag) {
	// int extra_bytes = 0;
	struct inet_sock *inet = inet_sk(sk);
	struct nd_conn_request* req = kzalloc(sizeof(*req), flag);
	struct nd_sock *nsk = nd_sk(sk);
	struct ndhdr* ack;

	// struct sk_buff* skb = __construct_control_skb(sk, 0);
	// struct nd_flow_sync_hdr* fh;
	// struct ndhdr* dh; 
	// pr_info("construct ack\n");
	if(unlikely(!req)) {
		WARN_ON(true);
		return NULL;
	}
	nd_init_request(sk, req);
	req->state = ND_CONN_SEND_CMD_PDU;
	ack = req->hdr;
	// req->pdu_len = sizeof(struct ndhdr);

	// fh = (struct nd_flow_sync_hdr *) skb_put(skb, sizeof(struct nd_flow_sync_hdr));
	
	// dh = (struct ndhdr*) (&sync->common);
	ack->len = 0;
	ack->type = ACK;
	ack->source = inet->inet_sport;
	ack->dest = inet->inet_dport;
	// sync->check = 0;
	ack->doff = (sizeof(struct ndhdr)) << 2;
	ack->grant_seq = htonl(nsk->receiver.grant_nxt);
	pr_info("ack grant seq:%u\n", htonl(ack->grant_seq));
	// fh->flow_id = message_id;
	// fh->flow_size = htonl(message_size);
	// fh->start_time = start_time;
	// extra_bytes = ND_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return req;
}

struct nd_conn_request* construct_fin_req(struct sock* sk) {
	// int extra_bytes = 0;
	struct inet_sock *inet = inet_sk(sk);
	struct nd_conn_request* req = kzalloc(sizeof(*req), GFP_KERNEL);
	struct ndhdr* sync;

	// struct sk_buff* skb = __construct_control_skb(sk, 0);
	// struct nd_flow_sync_hdr* fh;
	// struct ndhdr* dh; 
	if(unlikely(!req)) {
		WARN_ON(true);
		return NULL;
	}
	nd_init_request(sk, req);
	req->state = ND_CONN_SEND_CMD_PDU;
	sync = req->hdr;
	// req->pdu_len = sizeof(struct ndhdr);

	// fh = (struct nd_flow_sync_hdr *) skb_put(skb, sizeof(struct nd_flow_sync_hdr));
	
	// dh = (struct ndhdr*) (&sync->common);
	sync->len = 0;
	sync->type = FIN;
	sync->source = inet->inet_sport;
	sync->dest = inet->inet_dport;
	// sync->check = 0;
	sync->doff = (sizeof(struct ndhdr)) << 2;

	// fh->flow_id = message_id;
	// fh->flow_size = htonl(message_size);
	// fh->start_time = start_time;
	// extra_bytes = ND_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return req;
}
struct sk_buff* construct_token_pkt(struct sock* sk, unsigned short priority,
	 __u32 prev_grant_nxt, __u32 grant_nxt, bool handle_rtx) {
	// int extra_bytes = 0;
	struct nd_sock *dsk = nd_sk(sk);
	struct sk_buff* skb = __construct_control_skb(sk, ND_HEADER_MAX_SIZE
		 + dsk->num_sacks * sizeof(struct nd_sack_block_wire));
	struct nd_token_hdr* fh;
	struct ndhdr* dh;
	struct nd_sack_block_wire *sack;
	int i = 0;
	bool manual_end_point = true;
	if(unlikely(!skb)) {
		return NULL;
	}
	fh = (struct nd_token_hdr *) skb_put(skb, sizeof(struct nd_token_hdr));
	dh = (struct ndhdr*) (&fh->common);
	dh->len = htons(sizeof(struct nd_token_hdr));
	dh->type = TOKEN;
	fh->priority = priority;
	fh->rcv_nxt = dsk->receiver.rcv_nxt;
	fh->grant_nxt = grant_nxt;
	fh->num_sacks = 0;
	// printk("TOKEN: new grant next:%u\n", fh->grant_nxt);
	// printk("prev_grant_nxt:%u\n", prev_grant_nxt);
	// printk("new rcv_nxt:%u\n", dsk->receiver.rcv_nxt);
	// printk("copied seq:%u\n", dsk->receiver.copied_seq);
	if(handle_rtx && dsk->receiver.rcv_nxt < prev_grant_nxt) {
		// printk("rcv_nxt:%u\n", dsk->receiver.rcv_nxt);
		while(i < dsk->num_sacks) {
			__u32 start_seq = dsk->selective_acks[i].start_seq;
			__u32 end_seq = dsk->selective_acks[i].end_seq;

			if(start_seq > prev_grant_nxt)
				goto next;
			if(end_seq > prev_grant_nxt) {
				end_seq = prev_grant_nxt;
				manual_end_point = false;
			}

			sack = (struct nd_sack_block_wire*) skb_put(skb, sizeof(struct nd_sack_block_wire));
			sack->start_seq = htonl(start_seq);
			printk("start seq:%u\n", start_seq);
			printk("end seq:%u\n", end_seq);

			sack->end_seq = htonl(end_seq);
			fh->num_sacks++;
		next:
			i++;
		}
		if(manual_end_point) {
			sack = (struct nd_sack_block_wire*) skb_put(skb, sizeof(struct nd_sack_block_wire));
			sack->start_seq = htonl(prev_grant_nxt);
			sack->end_seq = htonl(prev_grant_nxt);
			printk("sack start seq:%u\n", prev_grant_nxt);
			fh->num_sacks++;
		}

	}

	// extra_bytes = ND_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_ack_pkt(struct sock* sk, __be32 rcv_nxt) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb(sk, 0);
	struct nd_ack_hdr* ah;
	struct ndhdr* dh; 
	if(unlikely(!skb)) {
		return NULL;
	}
	ah = (struct nd_ack_hdr *) skb_put(skb, sizeof(struct nd_ack_hdr));
	dh = (struct ndhdr*) (&ah->common);
	dh->len = htons(sizeof(struct nd_ack_hdr));
	dh->type = ACK;
	ah->rcv_nxt = rcv_nxt;
	// extra_bytes = ND_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_fin_pkt(struct sock* sk) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb(sk, 0);
	struct ndhdr* dh; 
	if(unlikely(!skb)) {
		return NULL;
	}
	dh = (struct ndhdr*) skb_put(skb, sizeof(struct ndhdr));
	dh->len = htons(sizeof(struct ndhdr));
	dh->type = FIN;
	// fh->message_id = message_id;
	// extra_bytes = ND_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_rts_pkt(struct sock* sk, unsigned short iter, int epoch, int remaining_sz) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb(sk, 0);
	struct nd_rts_hdr* fh;
	struct ndhdr* dh; 
	if(unlikely(!skb)) {
		return NULL;
	}
	fh = (struct nd_rts_hdr *) skb_put(skb, sizeof(struct nd_rts_hdr));
	dh = (struct ndhdr*) (&fh->common);
	dh->len = htons(sizeof(struct nd_rts_hdr));
	dh->type = RTS;
	fh->iter = iter;
	fh->epoch = epoch;
	fh->remaining_sz = remaining_sz;
	// extra_bytes = ND_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_grant_pkt(struct sock* sk, unsigned short iter, int epoch, int remaining_sz, bool prompt) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb(sk, 0);
	struct nd_grant_hdr* fh;
	struct ndhdr* dh; 
	if(unlikely(!skb)) {
		return NULL;
	}
	fh = (struct nd_grant_hdr *) skb_put(skb, sizeof(struct nd_grant_hdr));
	dh = (struct ndhdr*) (&fh->common);
	dh->len = htons(sizeof(struct nd_grant_hdr));
	dh->type = GRANT;
	fh->iter = iter;
	fh->epoch = epoch;
	fh->remaining_sz = remaining_sz;
	fh->prompt = prompt;
	// extra_bytes = ND_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_accept_pkt(struct sock* sk, unsigned short iter, int epoch) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb(sk, 0);
	struct nd_accept_hdr* fh;
	struct ndhdr* dh; 
	if(unlikely(!skb)) {
		return NULL;
	}
	fh = (struct nd_accept_hdr *) skb_put(skb, sizeof(struct nd_accept_hdr));
	dh = (struct ndhdr*) (&fh->common);
	dh->len = htons(sizeof(struct nd_accept_hdr));
	dh->type = ACCEPT;
	fh->iter = iter;
	fh->epoch = epoch;
	// extra_bytes = ND_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}
/**
 * nd_xmit_control() - Send a control packet to the other end of an RPC.
 * @type:      Packet type, such as NOTIFICATION.
 * @contents:  Address of buffer containing the contents of the packet.
 *             Only information after the common header must be valid;
 *             the common header will be filled in by this function.
 * @length:    Length of @contents (including the common header).
 * @rpc:       The packet will go to the socket that handles the other end
 *             of this RPC. Addressing info for the packet, including all of
 *             the fields of common_header except type, will be set from this.
 * 
 * Return:     Either zero (for success), or a negative errno value if there
 *             was a problem.
 */
// int nd_xmit_control(enum nd_packet_type type, struct sk_buff *skb,
// 	size_t len, struct flowi4 *fl4)
// {
// 	struct sock *sk = skb->sk;
// 	struct inet_sock *inet = inet_sk(sk);
// 	struct nd_header *dh = nd_hdr(skb);
// 	dh->type = type;
// 	dh->source = inet->inet_sport;
// 	dh->dest = fl4->fl4_dport;
// 	uh->check = 0;
// 	uh->len = htons(len);

// 	// if (rpc->is_client) {
// 	// 	h->sport = htons(rpc->hsk->client_port);
// 	// } else {
// 	// 	h->sport = htons(rpc->hsk->server_port);
// 	// }
// 	h->dport = htons(rpc->dport);
// 	h->id = rpc->id;
// 	return __nd_xmit_control(contents, length, rpc->peer, rpc->hsk);
// }


/**
 * __nd_xmit_control() - Lower-level version of nd_xmit_control: sends
 * a control packet.
 * @contents:  Address of buffer containing the contents of the packet.
 *             The caller must have filled in all of the information,
 *             including the common header.
 * @length:    Length of @contents.
 * @peer:      Destination to which the packet will be sent.
 * @hsk:       Socket via which the packet will be sent.
 * 
 * Return:     Either zero (for success), or a negative errno value if there
 *             was a problem.
 */
int nd_xmit_control(struct sk_buff* skb, struct sock *sk, int dport)
{
	// struct nd_hdr *h;
	int result;
	struct ndhdr* dh;
	struct inet_sock *inet = inet_sk(sk);
	// struct flowi4 *fl4 = &peer->flow.u.ip4;

	if(!skb) {
		return -1;
	}
	dh = nd_hdr(skb);
	dh->source = inet->inet_sport;
	dh->dest = inet->inet_dport;
	// dh->check = 0;
	dh->doff = (sizeof(struct ndhdr)) << 2;
	// inet->tos = IPTOS_LOWDELAY | IPTOS_PREC_NETCONTROL;
	skb->sk = sk;
	// dst_confirm_neigh(peer->dst, &fl4->daddr);
	dst_hold(__sk_dst_get(sk));
	// skb_dst_set(skb, __sk_dst_get(sk));
	// skb_get(skb);
	result = __ip_queue_xmit(sk, skb, &inet->cork.fl, IPTOS_LOWDELAY | IPTOS_PREC_NETCONTROL);
	if (unlikely(result != 0)) {
		// INC_METRIC(control_xmit_errors, 1);
		
		/* It appears that ip_queue_xmit frees skbuffs after
		 * errors; the following code is to raise an alert if
		 * this isn't actually the case. The extra skb_get above
		 * and kfree_skb below are needed to do the check
		 * accurately (otherwise the buffer could be freed and
		 * its memory used for some other purpose, resulting in
		 * a bogus "reference count").
		 */
		// if (refcount_read(&skb->users) > 1)
		// 	printk(KERN_NOTICE "ip_queue_xmit didn't free "
		// 			"ND control packet after error\n");
	}
	// kfree_skb(skb);
	// INC_METRIC(packets_sent[h->type - DATA], 1);
	return result;
}

/**
 *
 */
void nd_xmit_data(struct sk_buff *skb, struct nd_sock* dsk, bool free_token)
{
	struct sock* sk = (struct sock*)(dsk);
	struct sk_buff* oskb;
	oskb = skb;
	if (unlikely(skb_cloned(oskb))) 
		skb = pskb_copy(oskb,  sk_gfp_mask(sk, GFP_ATOMIC));
	else
		skb = skb_clone(oskb,  sk_gfp_mask(sk, GFP_ATOMIC));
	__nd_xmit_data(skb, dsk, free_token);
	/* change the state of queue and metadata*/

	// nd_unlink_write_queue(oskb, sk);
	nd_rbtree_insert(&sk->tcp_rtx_queue, oskb);
	WRITE_ONCE(dsk->sender.snd_nxt, ND_SKB_CB(oskb)->end_seq);
	// sk_wmem_queued_add(sk, -skb->truesize);

	// if (!skb_queue_empty(&sk->sk_write_queue)) {
	// 	struct sk_buff *skb = nd_send_head(sk);
	// 	WRITE_ONCE(dsk->sender.snd_nxt, ND_SKB_CB(skb)->end_seq);
	// 	__nd_xmit_data(skb, dsk);
	// }
	// while (msg->next_packet) {
	// 	// int priority = TOS_1;
	// 	struct sk_buff *skb = msg->next_packet;
	// 	// struct nd_sock* dsk = msg->dsk;
	// 	// int offset = homa_data_offset(skb);
		
	// 	// if (homa == NULL) {
	// 	// 	printk(KERN_NOTICE "NULL homa pointer in homa_xmit_"
	// 	// 		"data, state %d, shutdown %d, id %llu, socket %d",
	// 	// 		rpc->state, rpc->hsk->shutdown, rpc->id,
	// 	// 		rpc->hsk->client_port);
	// 	// 	BUG();
	// 	// }
		
	// 	// if (offset >= rpc->msgout.granted)
	// 	// 	break;
		
	// 	// if ((rpc->msgout.length - offset) >= homa->throttle_min_bytes) {
	// 	// 	if (!homa_check_nic_queue(homa, skb, force)) {
	// 	// 		homa_add_to_throttled(rpc);
	// 	// 		break;
	// 	// 	}
	// 	// }
		
	// 	// if (offset < rpc->msgout.unscheduled) {
	// 	// 	priority = homa_unsched_priority(homa, rpc->peer,
	// 	// 			rpc->msgout.length);
	// 	// } else {
	// 	// 	priority = rpc->msgout.sched_priority;
	// 	// }
	// 	msg->next_packet = *nd_next_skb(skb);
		
	// 	skb_get(skb);
	// 	__nd_xmit_data(skb, dsk);
	// 	force = false;
	// }
}

/**
 * __homa_xmit_data() - Handles packet transmission stuff that is common
 * to homa_xmit_data and homa_resend_data.
 * @skb:      Packet to be sent. The packet will be freed after transmission
 *            (and also if errors prevented transmission).
 * @rpc:      Information about the RPC that the packet belongs to.
 * @priority: Priority level at which to transmit the packet.
 */
void __nd_xmit_data(struct sk_buff *skb, struct nd_sock* dsk, bool free_token)
{
	int err;
	__u8 tos;
	// struct nd_data_hder *h = (struct nd_data_hder *)
	// 		skb_transport_header(skb);
	struct sock* sk = (struct sock*)dsk;
	struct inet_sock *inet = inet_sk(sk);
	struct nd_data_hdr *h;
	// struct ndhdr* dh;

	// dh = nd_hdr(skb);

	// dh->source = inet->inet_sport;

	// dh->dest = dport;

	// inet->tos = TOS_1;

	// set_priority(skb, rpc->hsk, priority);

	/* Update cutoff_version in case it has changed since the
	 * message was initially created.
	 */
	if(free_token) 
		tos = IPTOS_LOWDELAY | IPTOS_PREC_INTERNETCONTROL;
	else 
		tos = IPTOS_THROUGHPUT | IPTOS_PREC_IMMEDIATE;
	skb_push(skb, sizeof(struct nd_data_hdr) - sizeof(struct data_segment));
	skb_reset_transport_header(skb);
	h = (struct nd_data_hdr *)
				skb_transport_header(skb);
	dst_hold(__sk_dst_get(sk));
	// skb_dst_set(skb, peer->dst);
	skb->sk = sk;
	skb_dst_set(skb, __sk_dst_get(sk));
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = skb_transport_header(skb) - skb->head;
	// skb->csum_offset = offsetof(struct ndhdr, check);
	h->common.source = inet->inet_sport;
	h->common.dest = inet->inet_dport;
	// h->common.len = htons(ND_SKB_CB(skb)->end_seq - ND_SKB_CB(skb)->seq);
	// h->common.seq = htonl(ND_SKB_CB(skb)->seq);
	h->common.type = DATA;
	h->free_token = free_token;
	nd_set_doff(h);
	
	skb_set_hash_from_sk(skb, sk);

	// h->common.seq = htonl(200);
	err = __ip_queue_xmit(sk, skb, &inet->cork.fl, tos);
//	tt_record4("Finished queueing packet: rpc id %llu, offset %d, len %d, "
//			"next_offset %d",
//			h->common.id, ntohl(h->seg.offset), skb->len,
//			rpc->msgout.next_offset);
	if (err) {
		// INC_METRIC(data_xmit_errors, 1);
		
		/* It appears that ip_queue_xmit frees skbuffs after
		 * errors; the following code raises an alert if this
		 * isn't actually the case.
		 */
		if (refcount_read(&skb->users) > 1) {
			printk(KERN_NOTICE "ip_queue_xmit didn't free "
					"ND data packet after error\n");
			kfree_skb(skb);
		}
	}
	// INC_METRIC(packets_sent[0], 1);
}

/* Called with bottom-half processing disabled.
   assuming hold the socket lock */
int nd_write_timer_handler(struct sock *sk)
{    
	// struct nd_sock *dsk = nd_sk(sk);
	// struct sk_buff *skb;
	int sent_bytes = 0;
	// if(dsk->num_sacks > 0) {
	// 	// printk("retransmit\n");
	// 	nd_retransmit(sk);
	// }
	// while((skb = skb_dequeue(&sk->sk_write_queue)) != NULL) {
	// 	if (ND_SKB_CB(skb)->end_seq <= dsk->grant_nxt) {
	// 		nd_xmit_data(skb, dsk, false);
	// 		sent_bytes += ND_SKB_CB(skb)->end_seq - ND_SKB_CB(skb)->seq;
	// 	} else {
	// 		skb_queue_head(&sk->sk_write_queue, skb);
	// 		break;
	// 	}
	// }
	return sent_bytes;

//         struct inet_connection_sock *icsk = inet_csk(sk);
//         int event;
        
//         if (((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN)) ||
//             !icsk->icsk_pending)
//                 goto out;
        
//         if (time_after(icsk->icsk_timeout, jiffies)) {
//                 sk_reset_timer(sk, &icsk->icsk_retransmit_timer, icsk->icsk_timeout);
//                 goto out;
//         }
        
//         tcp_mstamp_refresh(tcp_sk(sk));
//         event = icsk->icsk_pending;
        
//         switch (event) {
//         case ICSK_TIME_REO_TIMEOUT:
//                 tcp_rack_reo_timeout(sk);
//                 break;
//         case ICSK_TIME_LOSS_PROBE:
//                 tcp_send_loss_probe(sk);
//                 break;
//         case ICSK_TIME_RETRANS:
//                 icsk->icsk_pending = 0;
//                 tcp_retransmit_timer(sk);
//                 break;
//         case ICSK_TIME_PROBE0:
//                 icsk->icsk_pending = 0;
//                 tcp_probe_timer(sk);
//                 break;
//         }

// out:
//         sk_mem_reclaim(sk);
}
