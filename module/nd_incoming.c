
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
#include <net/tcp.h>
#include <net/checksum.h>
#include <net/xfrm.h>
#include <trace/events/udp.h>
#include <linux/static_key.h>
#include <trace/events/skb.h>
#include <net/busy_poll.h>
#include "nd_impl.h"
#include <net/sock_reuseport.h>
#include <net/addrconf.h>
#include <net/udp_tunnel.h>

// #include "linux_nd.h"
 #include "net_nd.h"
// #include "net_ndlite.h"
#include "uapi_linux_nd.h"
#include "nd_impl.h"
#include "nd_host.h"
// #include "nd_hashtables.h"

// static inline struct sock *__nd4_lib_lookup_skb(struct sk_buff *skb,
// 						 __be16 sport, __be16 dport,
// 						 struct udp_table *ndtable)
// {
// 	const struct iphdr *iph = ip_hdr(skb);

// 	return __nd4_lib_lookup(dev_net(skb->dev), iph->saddr, sport,
// 				 iph->daddr, dport, inet_iif(skb),
// 				 inet_sdif(skb), ndtable, skb);
// }


static void nd_rfree(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;
	// struct kcm_sock *kcm = kcm_sk(sk);
	// struct kcm_mux *mux = kcm->mux;
	unsigned int len = skb->truesize;

	/* recycle to the page pool */
	nd_page_pool_recycle_pages(skb);
	// sk_mem_uncharge(sk, len);
	atomic_sub(len, &sk->sk_rmem_alloc);

	/* For reading rx_wait and rx_psock without holding lock */
	// smp_mb__after_atomic();

	// if (!kcm->rx_wait && !kcm->rx_psock &&
	//     sk_rmem_alloc_get(sk) < sk->sk_rcvlowat) {
	// 	spin_lock_bh(&mux->rx_lock);
	// 	kcm_rcv_ready(kcm);
	// 	spin_unlock_bh(&mux->rx_lock);
	// }
}


static inline bool nd_sack_extend(struct nd_sack_block *sp, u32 seq,
				  u32 end_seq)
{
	if (!after(seq, sp->end_seq) && !after(sp->start_seq, end_seq)) {
		if (before(seq, sp->start_seq))
			sp->start_seq = seq;
		if (after(end_seq, sp->end_seq))
			sp->end_seq = end_seq;
		return true;
	}
	return false;
}

/* Remove acknowledged frames from the retransmission queue. If our packet
 * is before the ack sequence we can discard it as it's confirmed to have
 * arrived at the other end.
 */
int nd_clean_rtx_queue(struct sock *sk)
{
	// const struct inet_connection_sock *icsk = inet_csk(sk);
	struct nd_sock *dsk = nd_sk(sk);
	// u64 first_ackt, last_ackt;
	// u32 prior_sacked = tp->sacked_out;
	// u32 reord = tp->snd_nxt;  lowest acked un-retx un-sacked seq 
	struct sk_buff *skb, *next;
	bool fully_acked = true;
	// long sack_rtt_us = -1L;
	// long seq_rtt_us = -1L;
	// long ca_rtt_us = -1L;
	// u32 pkts_acked = 0;
	// u32 last_in_flight = 0;
	// bool rtt_update;
	int flag = 0;

	// first_ackt = 0;

	for (skb = skb_rb_first(&sk->tcp_rtx_queue); skb; skb = next) {
		struct nd_skb_cb *scb = ND_SKB_CB(skb);
		// const u32 start_seq = scb->seq;
		// u8 sacked = scb->sacked;
		// u32 acked_pcount;

		// tcp_ack_tstamp(sk, skb, prior_snd_una);

		/* Determine how many packets and what bytes were acked, tso and else */
		if (after(scb->end_seq, dsk->sender.snd_una)) {
			// if (tcp_skb_pcount(skb) == 1 ||
			//     !after(tp->snd_una, scb->seq))
			// 	break;

			// acked_pcount = tcp_tso_acked(sk, skb);
			// if (!acked_pcount)
			// 	break;
			fully_acked = false;
		} else {
			// acked_pcount = tcp_skb_pcount(skb);
		}

		// if (unlikely(sacked & TCPCB_RETRANS)) {
		// 	if (sacked & TCPCB_SACKED_RETRANS)
		// 		tp->retrans_out -= acked_pcount;
		// 	flag |= FLAG_RETRANS_DATA_ACKED;
		// } else if (!(sacked & TCPCB_SACKED_ACKED)) {
		// 	last_ackt = tcp_skb_timestamp_us(skb);
		// 	WARN_ON_ONCE(last_ackt == 0);
		// 	if (!first_ackt)
		// 		first_ackt = last_ackt;

		// 	last_in_flight = TCP_SKB_CB(skb)->tx.in_flight;
		// 	if (before(start_seq, reord))
		// 		reord = start_seq;
		// 	if (!after(scb->end_seq, tp->high_seq))
		// 		flag |= FLAG_ORIG_SACK_ACKED;
		// }

		// if (sacked & TCPCB_SACKED_ACKED) {
		// 	tp->sacked_out -= acked_pcount;
		// } else if (tcp_is_sack(tp)) {
		// 	tp->delivered += acked_pcount;
		// 	if (!tcp_skb_spurious_retrans(tp, skb))
		// 		tcp_rack_advance(tp, sacked, scb->end_seq,
		// 				 tcp_skb_timestamp_us(skb));
		// }
		// if (sacked & TCPCB_LOST)
		// 	tp->lost_out -= acked_pcount;

		// tp->packets_out -= acked_pcount;
		// pkts_acked += acked_pcount;
		// tcp_rate_skb_delivered(sk, skb, sack->rate);

		/* Initial outgoing SYN's get put onto the write_queue
		 * just like anything else we transmit.  It is not
		 * true data, and if we misinform our callers that
		 * this ACK acks real data, we will erroneously exit
		 * connection startup slow start one packet too
		 * quickly.  This is severely frowned upon behavior.
		 */
		// if (likely(!(scb->tcp_flags & TCPHDR_SYN))) {
		// 	flag |= FLAG_DATA_ACKED;
		// } else {
		// 	flag |= FLAG_SYN_ACKED;
		// 	tp->retrans_stamp = 0;
		// }

		if (!fully_acked)
			break;

		next = skb_rb_next(skb);
		// if (unlikely(skb == tp->retransmit_skb_hint))
		// 	tp->retransmit_skb_hint = NULL;
		// if (unlikely(skb == tp->lost_skb_hint))
		// 	tp->lost_skb_hint = NULL;
		// tcp_highest_sack_replace(sk, skb, next);
		nd_rtx_queue_unlink_and_free(skb, sk);
		// sk_stream_write_space(sk);
	}
	// if (!skb)
	// 	tcp_chrono_stop(sk, TCP_CHRONO_BUSY);

	// if (likely(between(tp->snd_up, prior_snd_una, tp->snd_una)))
	// 	tp->snd_up = tp->snd_una;

	// if (skb && (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED))
	// 	flag |= FLAG_SACK_RENEGING;

	// if (likely(first_ackt) && !(flag & FLAG_RETRANS_DATA_ACKED)) {
	// 	seq_rtt_us = tcp_stamp_us_delta(tp->tcp_mstamp, first_ackt);
	// 	ca_rtt_us = tcp_stamp_us_delta(tp->tcp_mstamp, last_ackt);

	// 	if (pkts_acked == 1 && last_in_flight < tp->mss_cache &&
	// 	    last_in_flight && !prior_sacked && fully_acked &&
	// 	    sack->rate->prior_delivered + 1 == tp->delivered &&
	// 	    !(flag & (FLAG_CA_ALERT | FLAG_SYN_ACKED))) {
	// 		/* Conservatively mark a delayed ACK. It's typically
	// 		 * from a lone runt packet over the round trip to
	// 		 * a receiver w/o out-of-order or CE events.
	// 		 */
	// 		flag |= FLAG_ACK_MAYBE_DELAYED;
	// 	}
	// }
	// if (sack->first_sackt) {
	// 	sack_rtt_us = tcp_stamp_us_delta(tp->tcp_mstamp, sack->first_sackt);
	// 	ca_rtt_us = tcp_stamp_us_delta(tp->tcp_mstamp, sack->last_sackt);
	// }
	// rtt_update = tcp_ack_update_rtt(sk, flag, seq_rtt_us, sack_rtt_us,
	// 				ca_rtt_us, sack->rate);

	// if (flag & FLAG_ACKED) {
	// 	flag |= FLAG_SET_XMIT_TIMER;  /* set TLP or RTO timer */
	// 	if (unlikely(icsk->icsk_mtup.probe_size &&
	// 		     !after(tp->mtu_probe.probe_seq_end, tp->snd_una))) {
	// 		tcp_mtup_probe_success(sk);
	// 	}

	// 	if (tcp_is_reno(tp)) {
	// 		tcp_remove_reno_sacks(sk, pkts_acked);

	// 		/* If any of the cumulatively ACKed segments was
	// 		 * retransmitted, non-SACK case cannot confirm that
	// 		 * progress was due to original transmission due to
	// 		 * lack of TCPCB_SACKED_ACKED bits even if some of
	// 		 * the packets may have been never retransmitted.
	// 		 */
	// 		if (flag & FLAG_RETRANS_DATA_ACKED)
	// 			flag &= ~FLAG_ORIG_SACK_ACKED;
	// 	} else {
	// 		int delta;

	// 		/* Non-retransmitted hole got filled? That's reordering */
	// 		if (before(reord, prior_fack))
	// 			tcp_check_sack_reordering(sk, reord, 0);

	// 		delta = prior_sacked - tp->sacked_out;
	// 		tp->lost_cnt_hint -= min(tp->lost_cnt_hint, delta);
	// 	}
	// } else if (skb && rtt_update && sack_rtt_us >= 0 &&
	// 	   sack_rtt_us > tcp_stamp_us_delta(tp->tcp_mstamp,
	// 					    tcp_skb_timestamp_us(skb))) {
	// 	/* Do not re-arm RTO if the sack RTT is measured from data sent
	// 	 * after when the head was last (re)transmitted. Otherwise the
	// 	 * timeout may continue to extend in loss recovery.
	// 	 */
	// 	flag |= FLAG_SET_XMIT_TIMER;  /* set TLP or RTO timer */
	// }

	// if (icsk->icsk_ca_ops->pkts_acked) {
	// 	struct ack_sample sample = { .pkts_acked = pkts_acked,
	// 				     .rtt_us = sack->rate->rtt_us,
	// 				     .in_flight = last_in_flight };

	// 	icsk->icsk_ca_ops->pkts_acked(sk, &sample);
	// }
	return flag;
}

/* If we update dsk->receiver.rcv_nxt, also update dsk->receiver.bytes_received 
 * and send ack pkt if the flow is finished */
 
static void nd_rcv_nxt_update(struct nd_sock *nsk, u32 seq)
{
	// struct sock *sk = (struct sock*) nsk;
	// struct inet_sock *inet = inet_sk(sk);
	u32 delta = seq - (u32)atomic_read(&nsk->receiver.rcv_nxt);
	// u32 new_grant_nxt;
	// int grant_bytes = calc_grant_bytes(sk);

	nsk->receiver.bytes_received += delta;
	atomic_set(&nsk->receiver.rcv_nxt, seq);
	// printk("update the rcvnext :%u\n", nsk->receiver.rcv_nxt);
	// new_grant_nxt = nd_window_size(nsk) + nsk->receiver.rcv_nxt;
	// if(new_grant_nxt - nsk->receiver.grant_nxt <= nsk->default_win) {
	// 	/* send ack pkt for new window */
	// 	 nsk->receiver.grant_nxt = new_grant_nxt;
	// 	nd_conn_queue_request(construct_ack_req(sk), false, true);
	// 	// pr_info("grant next update:%u\n", nsk->receiver.grant_nxt);
	// } else {
	// 	pr_info("new_grant_nxt: %u\n", new_grant_nxt);
	// 	pr_info("old grant nxt:%u\n", nsk->receiver.grant_nxt);
	// 	pr_info("nd_window_size(nsk):%u\n", nd_window_size(nsk));
	// }
	// if(dsk->receiver.rcv_nxt >= dsk->receiver.last_ack + dsk->receiver.max_grant_batch) {
	// 	// nd_xmit_control(construct_ack_pkt(sk, dsk->receiver.rcv_nxt), sk, inet->inet_dport); 
	// 	dsk->receiver.last_ack = dsk->receiver.rcv_nxt;
	// }
}

static inline void nd_send_grant(struct nd_sock *nsk, bool sync) {
	struct sock *sk = (struct sock*)nsk;
	gfp_t flag = sync? GFP_KERNEL: GFP_ATOMIC;
	u32 new_grant_nxt;
	new_grant_nxt = nd_window_size(nsk) + (u32)atomic_read(&nsk->receiver.rcv_nxt);
	
	// printk("new grant nxt:%u\n", new_);
	if(new_grant_nxt - nsk->receiver.grant_nxt <= nsk->default_win && new_grant_nxt != nsk->receiver.grant_nxt
		&& new_grant_nxt - nsk->receiver.grant_nxt >= nsk->default_win / 16) {
		/* send ack pkt for new window */
		 nsk->receiver.grant_nxt = new_grant_nxt;
		nd_conn_queue_request(construct_ack_req(sk, flag), nsk, sync, true, true);
		if(nd_params.nd_debug)
			pr_info("grant next update:%u\n", nsk->receiver.grant_nxt);
	} else {
		// if(nd_params.nd_debug) {
		// 	pr_info("new_grant_nxt: %u\n", new_grant_nxt);
		// 	pr_info("old grant nxt:%u\n", nsk->receiver.grant_nxt);
		// 	pr_info("nd_window_size(nsk):%u\n", nd_window_size(nsk));
		// }
	}
}
static void nd_drop(struct sock *sk, struct sk_buff *skb)
{
        sk_drops_add(sk, skb);
        // __kfree_skb(skb);
}

static void nd_v4_fill_cb(struct sk_buff *skb,
                           const struct ndhdr *dh)
{
        /* This is tricky : We move IPCB at its correct location into TCP_SKB_CB()
         * barrier() makes sure compiler wont play fool^Waliasing games.
         */
        // memmove(&ND_SKB_CB(skb)->header.h4, IPCB(skb),
        //         sizeof(struct inet_skb_parm));
        barrier();
        ND_SKB_CB(skb)->seq = ntohl(dh->seq);
        // printk("skb len:%d\n", skb->len);
        // printk("segment length:%d\n", ntohl(dh->seg.segment_length));
        ND_SKB_CB(skb)->end_seq = ND_SKB_CB(skb)->seq + skb->len - dh->doff / 4;
        // TCP_SKB_CB(skb)->ack_seq = ntohl(th->ack_seq);
        // TCP_SKB_CB(skb)->tcp_flags = tcp_flag_byte(th);
        // TCP_SKB_CB(skb)->tcp_tw_isn = 0;
        // TCP_SKB_CB(skb)->ip_dsfield = ipv4_get_dsfield(iph);
        // TCP_SKB_CB(skb)->sacked  = 0;
        // TCP_SKB_CB(skb)->has_rxtstamp =
        //                 skb->tstamp || skb_hwtstamps(skb)->hwtstamp;
}


/**
 * nd_try_coalesce - try to merge skb to prior one
 * @sk: socket
 * @dest: destination queue
 * @to: prior buffer
 * @from: buffer to add in queue
 * @fragstolen: pointer to boolean
 *
 * Before queueing skb @from after @to, try to merge them
 * to reduce overall memory use and queue lengths, if cost is small.
 * Packets in ofo or receive queues can stay a long time.
 * Better try to coalesce them right now to avoid future collapses.
 * Returns true if caller should free @from instead of queueing it
 */
static bool nd_try_coalesce(struct sock *sk,
			     struct sk_buff *to,
			     struct sk_buff *from,
			     bool *fragstolen)
{
	int delta;
	// int skb_truesize = from->truesize;
	*fragstolen = false;
	/* Its possible this segment overlaps with prior segment in queue */
	if (ND_SKB_CB(from)->seq != ND_SKB_CB(to)->end_seq)
		return false;
	// pr_info("to len: %d\n", to->len);
	// pr_info("to truesize len: %d\n", to->truesize);

	// pr_info("from truesize: %d\n", from->truesize);
	// if (skb_headlen(from) != 0) { 
	// 	delta = from->truesize - SKB_DATA_ALIGN(sizeof(struct sk_buff));
	// } else {
	// 	delta = from->truesize - SKB_TRUESIZE(skb_end_offset(from);
	// }
	// pr_info("from skb len :%d\n", from->len);
	// pr_info(" SKB_TRUESIZE(skb_end_offset(from):%d\n", skb_end_offset(from));s
	if (!skb_try_coalesce(to, from, fragstolen, &delta))
		return false;
	/* assume we have alrady add true size beforehand*/
	atomic_add(delta, &sk->sk_rmem_alloc);
	// sk_mem_charge(sk, delta);
	// NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPRCVCOALESCE);
	ND_SKB_CB(to)->end_seq = ND_SKB_CB(from)->end_seq;
	// ND_SKB_CB(to)->ack_seq = ND_SKB_CB(from)->ack_seq;
	// ND_SKB_CB(to)->tcp_flags |= ND_SKB_CB(from)->tcp_flags;

	// if (ND_SKB_CB(from)->has_rxtstamp) {
	// 	TCP_SKB_CB(to)->has_rxtstamp = true;
	// 	to->tstamp = from->tstamp;
	// 	skb_hwtstamps(to)->hwtstamp = skb_hwtstamps(from)->hwtstamp;
	// }

	return true;
}

// u32 ofo_queue = 0;
static int nd_data_queue_ofo(struct sock *sk, struct sk_buff *skb)
{
	struct nd_sock *dsk = nd_sk(sk);
	struct rb_node **p, *parent;
	struct sk_buff *skb1;
	u32 seq, end_seq;
	/* Disable header prediction. */
	// tp->pred_flags = 0;
	// inet_csk_schedule_ack(sk);
	// pr_info("get outof order packet\n");
	// tp->rcv_ooopack += max_t(u16, 1, skb_shinfo(skb)->gso_segs);
	// NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPOFOQUEUE);
	seq = ND_SKB_CB(skb)->seq;
	end_seq = ND_SKB_CB(skb)->end_seq;

	// printk("insert to data queue ofo:%d\n", seq);

	p = &dsk->out_of_order_queue.rb_node;
	if (RB_EMPTY_ROOT(&dsk->out_of_order_queue)) {
		/* Initial out of order segment, build 1 SACK. */
		// if (tcp_is_sack(tp)) {
		// 	tp->rx_opt.num_sacks = 1;
		// 	tp->selective_acks[0].start_seq = seq;
		// 	tp->selective_acks[0].end_seq = end_seq;
		// }
		rb_link_node(&skb->rbnode, NULL, p);
		rb_insert_color(&skb->rbnode, &dsk->out_of_order_queue);
		// tp->ooo_last_skb = skb;
		goto end;
	}

	/* In the typical case, we are adding an skb to the end of the list.
	 * Use of ooo_last_skb avoids the O(Log(N)) rbtree lookup.
	 */
// 	if (tcp_ooo_try_coalesce(sk, tp->ooo_last_skb,
// 				 skb, &fragstolen)) {
// coalesce_done:
// 		tcp_grow_window(sk, skb);
// 		kfree_skb_partial(skb, fragstolen);
// 		skb = NULL;
// 		goto add_sack;
// 	}
// 	 Can avoid an rbtree lookup if we are adding skb after ooo_last_skb 
// 	if (!before(seq, TCP_SKB_CB(tp->ooo_last_skb)->end_seq)) {
// 		parent = &tp->ooo_last_skb->rbnode;
// 		p = &parent->rb_right;
// 		goto insert;
// 	}

	/* Find place to insert this segment. Handle overlaps on the way. */
	parent = NULL;
	while (*p) {
		parent = *p;
		skb1 = rb_to_skb(parent);
		if (before(seq, ND_SKB_CB(skb1)->seq)) {
			p = &parent->rb_left;
			continue;
		}
		if (before(seq, ND_SKB_CB(skb1)->end_seq)) {
			if (!after(end_seq, ND_SKB_CB(skb1)->end_seq)) {
				/* All the bits are present. Drop. */
				nd_rmem_free_skb(sk, skb);
				nd_drop(sk, skb);
				skb = NULL;

				// tcp_dsack_set(sk, seq, end_seq);
				goto add_sack;
			}
			if (after(seq, ND_SKB_CB(skb1)->seq)) {
				/* Partial overlap. */
				// tcp_dsack_set(sk, seq, TCP_SKB_CB(skb1)->end_seq);
			} else {
				/* skb's seq == skb1's seq and skb covers skb1.
				 * Replace skb1 with skb.
				 */
				rb_replace_node(&skb1->rbnode, &skb->rbnode,
						&dsk->out_of_order_queue);
				// tcp_dsack_extend(sk,
				// 		 TCP_SKB_CB(skb1)->seq,
				// 		 TCP_SKB_CB(skb1)->end_seq);
				// NET_INC_STATS(sock_net(sk),
				// 	      LINUX_MIB_TCPOFOMERGE);
				nd_rmem_free_skb(sk, skb1);
				nd_drop(sk, skb1);
				goto merge_right;
			}
		} 
		// else if (tcp_ooo_try_coalesce(sk, skb1,
		// 				skb, &fragstolen)) {
		// 	goto coalesce_done;
		// }
		p = &parent->rb_right;
	}
// insert:
	/* Insert segment into RB tree. */
	rb_link_node(&skb->rbnode, parent, p);
	rb_insert_color(&skb->rbnode, &dsk->out_of_order_queue);
merge_right:
	/* Remove other segments covered by skb. */
	while ((skb1 = skb_rb_next(skb)) != NULL) {
		if (!after(end_seq, ND_SKB_CB(skb1)->seq))
			break;
		if (before(end_seq, ND_SKB_CB(skb1)->end_seq)) {
			// tcp_dsack_extend(sk, TCP_SKB_CB(skb1)->seq,
			// 		 end_seq);
			break;
		}
		rb_erase(&skb1->rbnode, &dsk->out_of_order_queue);
		// tcp_dsack_extend(sk, TCP_SKB_CB(skb1)->seq,
		// 		 TCP_SKB_CB(skb1)->end_seq);
		// NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPOFOMERGE);
		nd_rmem_free_skb(sk, skb1);
		nd_drop(sk, skb1);

	}
	/* If there is no skb after us, we are the last_skb ! */
	// if (!skb1)
	// 	tp->ooo_last_skb = skb;
add_sack:
	// if (tcp_is_sack(tp))
	// nd_sack_new_ofo_skb(sk, seq, end_seq);
end:
	if(skb) {
		skb->sk = sk;
		skb->destructor = nd_rfree;
		atomic_add(skb->truesize, &sk->sk_rmem_alloc);
		// sk_mem_charge(sk, skb->truesize);
		// ofo_queue += skb->len;
		// pr_info("ofo queue length:%u\n", ofo_queue);
	}
	return 0;
	// if (skb) {
	// 	tcp_grow_window(sk, skb);
	// 	skb_condense(skb);
	// 	skb_set_owner_r(skb, sk);
	// }
}

static void nd_ofo_queue(struct sock *sk)
{
	struct nd_sock *dsk = nd_sk(sk);
	// __u32 dsack_high = nd->receiver.rcv_nxt;
	bool fragstolen, eaten;
	// bool fin;
	struct sk_buff *skb, *tail;
	struct rb_node *p;
	// bool first = true;
	// u32 start = 0, end = 0;
	p = rb_first(&dsk->out_of_order_queue);
	while (p) {
		skb = rb_to_skb(p);
		if (after(ND_SKB_CB(skb)->seq,(u32)atomic_read(&dsk->receiver.rcv_nxt)))
			break;
		// ofo_queue -= skb->len;

		// if (before(ND_SKB_CB(skb)->seq, dsack_high)) {
		// 	// __u32 dsack = dsack_high;
		// 	// if (before(TCP_SKB_CB(skb)->end_seq, dsack_high))
		// 	// 	dsack_high = TCP_SKB_CB(skb)->end_seq;
		// 	// tcp_dsack_extend(sk, TCP_SKB_CB(skb)->seq, dsack);
		// }
		p = rb_next(p);
		rb_erase(&skb->rbnode, &dsk->out_of_order_queue);
		if (unlikely(!after(ND_SKB_CB(skb)->end_seq, (u32)atomic_read(&dsk->receiver.rcv_nxt)))) {
			nd_rmem_free_skb(sk, skb);
			nd_drop(sk, skb);
			continue;
		}
		// if (first) {
		// 	first = false;
		// 	start =  ND_SKB_CB(skb)->seq;
		// }
		// end = ND_SKB_CB(skb)->end_seq;
		tail = skb_peek_tail(&sk->sk_receive_queue);
		eaten = tail && nd_try_coalesce(sk, tail, skb, &fragstolen);
		nd_rcv_nxt_update(dsk, ND_SKB_CB(skb)->end_seq);
		// fin = TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN;
		if (!eaten)
			__skb_queue_tail(&sk->sk_receive_queue, skb);
		else
			kfree_skb_partial(skb, fragstolen);

		// if (unlikely(fin)) {
		// 	tcp_fin(sk);
		// 	 tcp_fin() purges tp->out_of_order_queue,
		// 	 * so we must end this loop right now.
			 
		// 	break;
		// }
	}
	// if(end - start != 0)
	// 	pr_info("diff:%d\n", end - start);
}

// void nd_data_ready(struct sock *sk)
// {
//         const struct nd_sock *dsk = nd_sk(sk);
//         int avail = dsk->receiver.rcv_nxt - dsk->receiver.copied_seq;

//         if ((avail < sk->sk_rcvlowat && dsk->receiver.rcv_nxt != dsk->total_length) && !sock_flag(sk, SOCK_DONE)) {
//         	return;
//         }
//         sk->sk_data_ready(sk);
// }

int nd_handle_sync_pkt(struct sk_buff *skb) {
	// struct nd_sock *dsk;
	// struct inet_sock *inet;
	// struct nd_peer *peer;
	// struct iphdr *iph;
	// struct message_hslot* slot;
	struct ndhdr *fh;
	struct sock *sk = NULL, *child;
	struct nd_sock *nsk;
	int sdif = inet_sdif(skb);
	bool refcounted = false;
	if (!pskb_may_pull(skb, sizeof(struct ndhdr))) {
		goto drop;		/* No space for header. */
	}
	fh =  nd_hdr(skb);
	// sk = skb_steal_sock(skb);
	// if(!sk) {
		// printk("fh->source:%d\n", ntohs(fh->source));
		// printk("fh->dest:%d\n", ntohs(fh->dest));
	// printk ("dev_net(skb_dst(skb)->dev): %d \n",(skb_dst(skb) == NULL));
	// printk("sdif:%d\n", sdif);
	sk = __nd_lookup_skb(&nd_hashinfo, skb, __nd_hdrlen(fh), fh->source,
		fh->dest, sdif, &refcounted);
		// sk = __nd4_lib_lookup_skb(skb, fh->common.source, fh->common.dest, &nd_table);
	// }
	if(sk) {
		child = nd_conn_request(sk, skb);
		if(child) {
			nsk = nd_sk(child);
			// struct nd_sock *dsk = nd_sk(child);
			// if(dsk->total_length >= nd_params.short_flow_size) {
			// 	rcv_handle_new_flow(dsk);
			// } else {
			// 	/* set short flow timer */
			// 	hrtimer_start(&dsk->receiver.flow_wait_timer, ns_to_ktime(nd_params.rtt * 1000), 
			// 	HRTIMER_MODE_REL_PINNED_SOFT);
			// }
			/* currently assume at the target side */
			/* ToDo: sync can be true; */
			nd_conn_queue_request(construct_sync_ack_req(child), nsk, false, true, true);
		}
	} else {
		goto free;
	}


drop:
    if (refcounted) {
        sock_put(sk);
    }
free:
	kfree_skb(skb);

	return 0;
}

// ktime_t start, end;
// __u32 backlog_time = 0;
int nd_handle_token_pkt(struct sk_buff *skb) {
	struct nd_sock *dsk;
	// struct inet_sock *inet;
	// struct nd_peer *peer;
	// struct iphdr *iph;
	struct nd_token_hdr *th;
	struct sock *sk;
	int sdif = inet_sdif(skb);
	bool refcounted = false;

	if (!pskb_may_pull(skb, sizeof(struct nd_token_hdr))) {
		kfree_skb(skb);
		return 0;
	}
	th = nd_token_hdr(skb);
	sk = __nd_lookup_skb(&nd_hashinfo, skb, __nd_hdrlen(&th->common), th->common.source,
            th->common.dest, sdif, &refcounted);
	if(sk) {
 		dsk = nd_sk(sk);
 		bh_lock_sock(sk);
 		skb->sk = sk;
 		// if (!sock_owned_by_user(sk)) {
			/* clean rtx queue */
		dsk->sender.snd_una = th->rcv_nxt > dsk->sender.snd_una ? th->rcv_nxt: dsk->sender.snd_una;
		/* add token */
 		// dsk->grant_nxt = th->grant_nxt > dsk->grant_nxt ? th->grant_nxt : dsk->grant_nxt;
 	// 	/* add sack info */
 	// 	nd_get_sack_info(sk, skb);
		// /* start doing transmission (this part may move to different places later)*/
	    if(!sock_owned_by_user(sk)) {
	    	// sock_rps_save_rxhash(sk, skb);
	 		nd_clean_rtx_queue(sk);
	    } else {
	 		test_and_set_bit(ND_CLEAN_TIMER_DEFERRED, &sk->sk_tsq_flags);
	    }
	 //    if(!sock_owned_by_user(sk) || dsk->num_sacks == 0) {
	 // 		nd_write_timer_handler(sk);
	 //    } else {
	 // 		test_and_set_bit(ND_RTX_DEFERRED, &sk->sk_tsq_flags);
	 //    }

        // } else {
        // 	// if(backlog_time % 100 == 0) {
        // 		// end = ktime_get();
        // 		// printk("time diff:%llu\n", ktime_to_us(ktime_sub(end, start)));
        // 		// printk("num of backlog_time:%d\n", backlog_time);
        // 	// }
        //     nd_add_backlog(sk, skb, true);
        // }
        bh_unlock_sock(sk);
		// xmit_handle_new_token(&xmit_core_tab, skb);
	} else {
		kfree_skb(skb);
	};
	// kfree_skb(skb);

    if (refcounted) {
        sock_put(sk);
    }
	return 0;
}

int nd_handle_ack_pkt(struct sk_buff *skb) {
	struct nd_sock *dsk;
	// struct inet_sock *inet;
	// struct nd_peer *peer;
	// struct iphdr *iph;
	// struct ndhdr *dh;
	struct ndhdr *ah;
	struct sock *sk;
	int sdif = inet_sdif(skb);
	bool refcounted = false;
	int err = 0;
	if (!pskb_may_pull(skb, sizeof(struct ndhdr))) {
		kfree_skb(skb);		/* No space for header. */
		return 0;
	}
	ah = nd_hdr(skb);
	// sk = skb_steal_sock(skb);
	// if(!sk) {
	sk = __nd_lookup_skb(&nd_hashinfo, skb, __nd_hdrlen(ah), ah->source,
            ah->dest, sdif, &refcounted);
    // }
	if(nd_params.nd_debug)
		pr_info("receive ack:%u\n", ntohl(ah->grant_seq));
	if(sk) {
 		bh_lock_sock(sk);
		dsk = nd_sk(sk);
	// 	// dsk->sender.snd_una = ah->grant_seq > dsk->sender.snd_una ? ah->rcv_nxt: dsk->sender.snd_una;
		if (!sock_owned_by_user(sk)) {
			if(ntohl(ah->grant_seq) - dsk->sender.sd_grant_nxt <= dsk->default_win) {
				dsk->sender.sd_grant_nxt = ntohl(ah->grant_seq);
				err = nd_push(sk, GFP_ATOMIC);
				if(sk_stream_memory_free(sk)) {
					sk->sk_write_space(sk);
				} 
				/* might need to remove this logic */
				else if(err == -EDQUOT){
					/* push back since there is no space */
					nd_conn_add_sleep_sock(dsk->nd_ctrl, dsk);
				}
			}

			kfree_skb(skb);
        } else {
			nd_add_backlog(sk, skb, true);
	 		// test_and_set_bit(ND_CLEAN_TIMER_DEFERRED, &sk->sk_tsq_flags);
	    }
    	bh_unlock_sock(sk);
	   
	} else {
		kfree_skb(skb);
	}

    if (refcounted) {
        sock_put(sk);
    }

	return 0;
}


int nd_handle_sync_ack_pkt(struct sk_buff *skb) {
	// struct nd_sock *dsk;
	// struct inet_sock *inet;
	// struct nd_peer *peer;
	// struct iphdr *iph;
	// struct ndhdr *dh;
	struct ndhdr *nh;
	struct sock *sk;
	int sdif = inet_sdif(skb);
	bool refcounted = false;
	if (!pskb_may_pull(skb, sizeof(struct ndhdr))) {
		kfree_skb(skb);		/* No space for header. */
		return 0;
	}
	nh = nd_hdr(skb);
	// sk = skb_steal_sock(skb);
	// if(!sk) {
	// pr_info("read src port:%d\n", ntohs(nh->source));
	// pr_info("read dst port:%d\n", ntohs(nh->dest));
	// pr_info("receive sync ack pkt\n");
	sk = __nd_lookup_skb(&nd_hashinfo, skb, __nd_hdrlen(nh), nh->source,
            nh->dest, sdif, &refcounted);
    // }
	if(sk) {
		bh_lock_sock(sk);
		if(!sock_owned_by_user(sk)) {
			sk->sk_state = ND_ESTABLISH;
			sk->sk_data_ready(sk);
			kfree_skb(skb);
		} else {
			nd_add_backlog(sk, skb, true);
		}
		bh_unlock_sock(sk);
		if (refcounted) {
			sock_put(sk);
		}
		return 0;
	} else {
		kfree_skb(skb);
		printk("didn't find the socket\n");
	}
	return 0;
}

int nd_handle_fin_pkt(struct sk_buff *skb) {
	struct nd_sock *dsk;
	// struct inet_sock *inet;
	// struct nd_peer *peer;
	// struct iphdr *iph;
	struct ndhdr *dh;
	struct sock *sk;
	int sdif = inet_sdif(skb);
	bool refcounted = false;

	// if (!pskb_may_pull(skb, sizeof(struct nd_ack_hdr))) {
	// 	kfree_skb(skb);		/* No space for header. */
	// 	return 0;
	// }
	// printk("receive fin pkt\n");
	dh = nd_hdr(skb);
	// sk = skb_steal_sock(skb);
	// if(!sk) {
	sk = __nd_lookup_skb(&nd_hashinfo, skb, __nd_hdrlen(dh), dh->source,
            dh->dest, sdif, &refcounted);
    // }
	if(sk) {
 		bh_lock_sock(sk);
		dsk = nd_sk(sk);
		if (!sock_owned_by_user(sk)) {
			// printk("reach here:%d", __LINE__);

	        nd_set_state(sk, TCP_CLOSE);
	        nd_write_queue_purge(sk);
	        sk->sk_data_ready(sk);
	        kfree_skb(skb);
        } else {
			// printk("put fin to backlog:%d", __LINE__);
            nd_add_backlog(sk, skb, true);
        }
        bh_unlock_sock(sk);

		// printk("socket address: %p LINE:%d\n", dsk,  __LINE__);

	} else {
		kfree_skb(skb);
		printk("doesn't find dsk address LINE:%d\n", __LINE__);
	}

    if (refcounted) {
        sock_put(sk);
    }

	return 0;
}


static int  nd_queue_rcv(struct sock *sk, struct sk_buff *skb,  bool *fragstolen)
{
	int eaten;
	struct sk_buff *tail = skb_peek_tail(&sk->sk_receive_queue);

	eaten = (tail &&
		 nd_try_coalesce(sk, tail,
				  skb, fragstolen)) ? 1 : 0;
	if (!eaten) {
		skb->sk = sk;
		skb->destructor = nd_rfree;
		atomic_add(skb->truesize, &sk->sk_rmem_alloc);
		// sk_mem_charge(sk, skb->truesize);
		__skb_queue_tail(&sk->sk_receive_queue, skb);
		
		// skb_set_owner_r(skb, sk);
	}
	nd_rcv_nxt_update(nd_sk(sk), ND_SKB_CB(skb)->end_seq);
	return eaten;
}

int nd_data_queue(struct sock *sk, struct sk_buff *skb)
{
	struct nd_sock *dsk = nd_sk(sk);
	bool fragstolen;
	int eaten;
	if (ND_SKB_CB(skb)->seq == ND_SKB_CB(skb)->end_seq) {
		nd_rmem_free_skb(sk, skb);
		return 0;
	}
	// if(WARN_ON(atomic_read(&sk->sk_rmem_alloc) > sk->sk_rcvbuf)) {
	// 	// struct inet_sock *inet = inet_sk(sk);
	//     // printk("seq num:%u\n", ND_SKB_CB(skb)->seq);
	//     // printk("inet sk dport:%d\n", ntohs(inet->inet_dport));
	//     // printk("discard packet due to memory:%d\n", __LINE__);
	// 	// sk_drops_add(sk, skb);
	// 	// kfree_skb(skb);
	// 	// return 0;
	// }
	// if (!sk_rmem_schedule(sk, skb, skb->truesize))
	// 	return -ENOBUFS;
	// atomic_add(skb->truesize, &sk->sk_rmem_alloc);

	// skb_dst_drop(skb);
	// __skb_pull(skb, nd_hdr(skb)->doff >> 2);
	// printk("handle packet data queue?:%d\n", ND_SKB_CB(skb)->seq);

	/*  Queue data for delivery to the user.
	 *  Packets in sequence go to the receive queue.
	 *  Out of sequence packets to the out_of_order_queue.
	 */
	if (ND_SKB_CB(skb)->seq == (u32)atomic_read(&dsk->receiver.rcv_nxt)) {
		// if (tcp_receive_window(tp) == 0) {
		// 	NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPZEROWINDOWDROP);
		// 	goto out_of_window;
		// }

		/* Ok. In sequence. In window. */
// queue_and_out:
		// if (skb_queue_len(&sk->sk_receive_queue) == 0)
		// 	sk_forced_mem_schedule(sk, skb->truesize);
		// else if (tcp_try_rmem_schedule(sk, skb, skb->truesize)) {
		// 	goto drop;
		// }
		// __skb_queue_tail(&sk->sk_receive_queue, skb);
queue_and_out:
		eaten = nd_queue_rcv(sk, skb, &fragstolen);

		if (!RB_EMPTY_ROOT(&dsk->out_of_order_queue)) {
			nd_ofo_queue(sk);
		}

		// 	/* RFC5681. 4.2. SHOULD send immediate ACK, when
		// 	 * gap in queue is filled.
		// 	 */
		// 	if (RB_EMPTY_ROOT(&dsk->out_of_order_queue))
		// 		inet_csk(sk)->icsk_ack.pending |= ICSK_ACK_NOW;
		// }

		// if (dsk->num_sacks)
		// 	nd_sack_remove(dsk);

		// tcp_fast_path_check(sk);

		if (eaten > 0)
			kfree_skb_partial(skb, fragstolen);
		return 0;
	}
	if (!after(ND_SKB_CB(skb)->end_seq, (u32)atomic_read(&dsk->receiver.rcv_nxt))) {
		printk("duplicate drop\n");
		printk("duplicate seq:%u\n", ND_SKB_CB(skb)->seq);
		nd_rmem_free_skb(sk, skb);
		nd_drop(sk, skb);
		return 0;
	}

	/* Out of window. F.e. zero window probe. */
	// if (!before(ND_SKB_CB(skb)->seq, dsk->rcv_nxt + tcp_receive_window(dsk)))
	// 	goto out_of_window;

	if (unlikely(before(ND_SKB_CB(skb)->seq, (u32)atomic_read(&dsk->receiver.rcv_nxt)))) {
		/* Partial packet, seq < rcv_next < end_seq; unlikely */
		// tcp_dsack_set(sk, ND_SKB_CB(skb)->seq, dsk->rcv_nxt);


		/* If window is closed, drop tail of packet. But after
		 * remembering D-SACK for its head made in previous line.
		 */
		// if (!tcp_receive_window(dsk)) {
		// 	NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPZEROWINDOWDROP);
		// 	goto out_of_window;
		// }
		goto queue_and_out;
	}

	nd_data_queue_ofo(sk, skb);
	return 0;
}

bool nd_add_backlog(struct sock *sk, struct sk_buff *skb, bool omit_check)
{
		// struct nd_sock *dsk = nd_sk(sk);
        u32 limit = READ_ONCE(sk->sk_rcvbuf) + READ_ONCE(sk->sk_sndbuf);
        // pr_info("put into the backlog\n:wq");
		// skb_condense(skb);

        /* Only socket owner can try to collapse/prune rx queues
         * to reduce memory overhead, so add a little headroom here.
         * Few sockets backlog are possibly concurrently non empty.
         */
        limit += 64*1024;
        if (omit_check) {
        	limit = UINT_MAX;
        }
        if (unlikely(sk_add_backlog(sk, skb, limit))) {
                bh_unlock_sock(sk);
                // __NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPBACKLOGDROP);
                return true;
        }
		/* sk_add_backlog add skb->truesize, but we have fraglist skbs */
		// sk->sk_backlog.len +=  ND_SKB_CB(skb)->total_size - skb->truesize;
        // atomic_add(skb->truesize, &dsk->receiver.backlog_len);

        return false;

 }

static void nd_handle_data_skb_new(struct sock* sk, struct sk_buff* skb) {
		// pr_info("ND_SKB_CB(head)->seq = seq:%u core:%d \n", ND_SKB_CB(skb)->seq, raw_smp_processor_id());
		__skb_pull(skb, nd_hdr(skb)->doff >> 2);
		nd_data_queue(sk, skb);
	return ;
}

/* assuming hold the bh lock of sock */
static void nd_handle_data_pkt_lock(struct sock *sk, struct sk_buff *skb) {
	if (!sock_owned_by_user(sk)) {
		/* current place to set rxhash for RFS/RPS */
		// printk("skb->hash:%u\n", skb->hash);
		// sock_rps_save_rxhash(sk, skb)
		//  printk("put into the data queue\n");
		nd_handle_data_skb_new(sk, skb);
		// nd_send_grant(dsk, false);
		if (!sock_flag(sk, SOCK_DEAD)) {
			sk->sk_data_ready(sk);
		}
		// nd_check_flow_finished_at_receiver(dsk);;
	} else {
		// printk("add to backlog: %d\n", raw_smp_processor_id());
		/* omit check for now */
		nd_add_backlog(sk, skb, true);
			// goto discard_and_relse;
	}
	return;
}
/**
 * nd_data_pkt() - Handler for incoming DATA packets
 * @skb:     Incoming packet; size known to be large enough for the header.
 *           This function now owns the packet.
 * 
 * Return: Zero means the function completed successfully. Nonzero means
 * that the RPC had to be unlocked and deleted because the socket has been
 * shut down; the caller should not access the RPC anymore. Note: this method
 * may change the RPC's state to RPC_READY.
 */
int nd_handle_data_pkt(struct sk_buff *skb)
{
	struct nd_sock *dsk;
	struct ndhdr *dh;
	struct sock *sk;
	struct sk_buff *wait_skb, *tmp;
	struct iphdr *iph;
	/* ToDo: get sdif value; now it is polluted by TCP layer */
	// int sdif = inet_sdif(skb);
	int sdif = 0;
	bool refcounted = false;
	bool discard = false;
	bool oversize = false;
	// printk("receive data pkt\n");
	if (!pskb_may_pull(skb, sizeof(struct ndhdr)))
		goto drop;		/* No space for header. */
	dh =  nd_hdr(skb);
	iph = ip_hdr(skb);
	// sk = skb_steal_sock(skb);
	// if(!sk) {
	// WARN_ON(skb_dst(skb) == NULL);
	// WARN_ON(skb_dst(skb)->dev == NULL);
	sk = __nd_lookup_skb(&nd_hashinfo, skb, __nd_hdrlen(dh), dh->source,
            dh->dest, sdif, &refcounted);
	// printk("dh->source:%d dh->dest:%d \n", dh->source, dh->dest);
	// printk("iph->saddr:%d iph->daddr:%d\n", iph->saddr, iph->daddr);
	// printk("__nd_hdrlen(dh):%d sdif:%d inet_iif(skb):%d \n", __nd_hdrlen(dh), sdif, inet_iif(skb));
    if(!sk) {
    	goto drop;
	}
	nd_v4_fill_cb(skb, dh);

    // }
	// printk("packet hash %u\n", skb->hash);
	// printk("oacket is l4 hash:%d\n", skb->l4_hash);
	// printk("receive packet core:%d\n", raw_smp_processor_id());
	// printk("dport:%d\n", ntohs(inet_sk(sk)->inet_dport));
	// printk("skb seq:%u\n", ND_SKB_CB(skb)->seq);
	// printk("skb address:%p\n", skb);
	if(sk) {
		dsk = nd_sk(sk);
		// iph = ip_hdr(skb);
 		bh_lock_sock(sk);
		if(sk->sk_state != ND_ESTABLISH){
			bh_unlock_sock(sk);
			goto drop;
		}
		/* To Do: check sk_hol_queue */
		skb_queue_walk_safe(&dsk->receiver.sk_hol_queue, wait_skb, tmp) {
			/* this might underestimate the current buffer size if socket is handling its backlog */
			if(ND_SKB_CB(wait_skb)->end_seq - (u32)atomic_read(&dsk->receiver.rcv_nxt) >=  nd_window_size(dsk)) {
				continue;
			}
			__skb_unlink(wait_skb, &dsk->receiver.sk_hol_queue);
			atomic_sub(wait_skb->truesize, &tcp_sk(ND_SKB_CB(wait_skb)->queue->sock->sk)->hol_alloc);
			atomic_sub(wait_skb->len, &tcp_sk(ND_SKB_CB(wait_skb)->queue->sock->sk)->hol_len);
			// printk("reduce hol alloc:%d\n", atomic_read(&tcp_sk(wait_skb->sk)->hol_alloc));
			if(atomic_read(&tcp_sk(ND_SKB_CB(wait_skb)->queue->sock->sk)->hol_alloc) == 0) {
				if(ndt_conn_is_latency(ND_SKB_CB(skb)->queue)) {
					queue_work_on(queue_cpu(ND_SKB_CB(skb)->queue), ndt_conn_wq_lat, &ND_SKB_CB(skb)->queue->delay_ack_work);
				} else {
					queue_work_on(queue_cpu(ND_SKB_CB(skb)->queue), ndt_conn_wq, &ND_SKB_CB(skb)->queue->delay_ack_work);
				}
				if(hrtimer_active(&ND_SKB_CB(skb)->queue->hol_timer)) {
					hrtimer_cancel(&ND_SKB_CB(skb)->queue->hol_timer);
				}
			}		
			ND_SKB_CB(wait_skb)->queue = NULL;
			nd_handle_data_pkt_lock(sk, wait_skb);

		}
        // ret = 0;
		// printk("atomic backlog len:%d\n", atomic_read(&dsk->receiver.backlog_len));
		/* this might underestimate the current buffer size if socket is handling its backlog */
		/* this part might needed to be changed later, because rcv_nxt */
		if(ND_SKB_CB(skb)->end_seq - (u32)atomic_read(&dsk->receiver.rcv_nxt) < nd_window_size(dsk)) {
			nd_handle_data_pkt_lock(sk, skb);
			// printk("handle data pkt lock seq:%u rcv next:%u core:%d\n",
			// 	ND_SKB_CB(skb)->seq, (u32)atomic_read(&dsk->receiver.rcv_nxt),  raw_smp_processor_id());	
			// printk("rcv_nxt:%u\n", (u32)atomic_read(&dsk->receiver.rcv_nxt));
		} else {
			// oversize = true;
			if(ND_SKB_CB(skb)->end_seq == (u32)atomic_read(&dsk->receiver.rcv_nxt)) {
				WARN_ON(true);
			}
			/* increment hol_alloc size of tcp socket */
			atomic_add(skb->truesize, &tcp_sk(ND_SKB_CB(skb)->queue->sock->sk)->hol_alloc);
			atomic_add(skb->len, &tcp_sk(ND_SKB_CB(skb)->queue->sock->sk)->hol_len);

			/* add to hol skb to the socket wait queue */
			__skb_queue_tail(&dsk->receiver.sk_hol_queue, skb);
			/* add to wait queue flags */
			test_and_set_bit(ND_WAIT_DEFERRED, &sk->sk_tsq_flags);
			// printk("add hol alloc:%d  seq:%u rcv next:%u copied seq:%u core:%d\n", atomic_read(&tcp_sk(ND_SKB_CB(skb)->queue->sock->sk)->hol_alloc),
			// 	ND_SKB_CB(skb)->seq, (u32)atomic_read(&dsk->receiver.rcv_nxt),  (u32)atomic_read(&dsk->receiver.copied_seq),  raw_smp_processor_id());
			// printk("rmem alloc:%d backlog len:%d \n", atomic_read(&sk->sk_rmem_alloc), sk->sk_backlog.len );	
			// printk("rcv_nxt:%u\n", (u32)atomic_read(&dsk->receiver.rcv_nxt));
		

		}
		/* handle the current pkt */
        bh_unlock_sock(sk);
	} else {
		// printk("discard pkt\n");
		discard = true;
	}
	
	if (discard) {
	    // printk("seq num:%u\n", ND_SKB_CB(skb)->seq);
	    // printk("discard packet:%d\n", __LINE__);
		// skb_dump(KERN_WARNING, skb, false);
		sk_drops_add(sk, skb);
		goto drop;
	}

    if (refcounted) {
        sock_put(sk);
    }

	/* packets have to be stuck in the nd channel */
	// if(oversize)
	// 	return -1;
    return 0;
drop:
    if (refcounted) {
        sock_put(sk);
    }
	printk("drop pkt\n");
    /* Discard frame. */
	// skb->queue = NULL;
    kfree_skb(skb);
    return -2;

// discard_and_relse:
//     printk("seq num:%u\n", ND_SKB_CB(skb)->seq);
//     printk("discard packet due to memory:%d\n", __LINE__);
//     sk_drops_add(sk, skb);
//     if (refcounted)
//             sock_put(sk);
//     goto drop;
	// kfree_skb(skb);
}

/* should hold the lock, before calling this function；
 * This function is only called for backlog handling from the release_sock()
 */
int nd_v4_do_rcv(struct sock *sk, struct sk_buff *skb) {
	struct ndhdr* dh;
    struct nd_sock *dsk = nd_sk(sk);
	int err = 0;
	dh = nd_hdr(skb);
	// atomic_sub(skb->truesize, &dsk->receiver.backlog_len);
	/* current place to set rxhash for RFS/RPS */
 	// sock_rps_save_rxhash(sk, skb);

	if(dh->type == DATA) {
		nd_handle_data_skb_new(sk, skb);
		// nd_send_grant(dsk, true);
		if (!sock_flag(sk, SOCK_DEAD)) {
			sk->sk_data_ready(sk);
		}
		return 0;
		// return __nd4_lib_rcv(skb, &nd_table, IPPROTO_VIRTUAL_SOCK);
	} else if (dh->type == FIN) {
		// printk("reach here:%d", __LINE__);

        nd_set_state(sk, TCP_CLOSE);
        nd_write_queue_purge(sk);
		// atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
		sk->sk_data_ready(sk);
	} else if (dh->type == ACK) {
		/*do nd push and check the seq */
		// pr_info("backlog:%u\n", ntohl(dh->grant_seq));
		// pr_info("receive ack in backlog\n");
		// pr_info("handle ack in backlog\n");
		if(ntohl(dh->grant_seq) - dsk->sender.sd_grant_nxt <= dsk->default_win) {
			dsk->sender.sd_grant_nxt = ntohl(dh->grant_seq);
		}
		/*has to do nd push and check seq */
		err = nd_push(sk, GFP_KERNEL);
		if(sk_stream_memory_free(sk)) {
			// pr_info("invoke write space in backlog\n");
			sk->sk_write_space(sk);
		} 
		else if(err == -EDQUOT){
			/* push back since there is no space */
			// pr_info("add sleep sock in backlog\n");
			nd_conn_add_sleep_sock(dsk->nd_ctrl, dsk);
		}
	} else if (dh->type == SYNC_ACK) {
		sk->sk_state = ND_ESTABLISH;
		sk->sk_data_ready(sk);
	}

	// else if (dh->type == TOKEN) {
	// 	/* clean rtx queue */
	// 	struct nd_token_hdr *th = nd_token_hdr(skb);
	// 	dsk->sender.snd_una = th->rcv_nxt > dsk->sender.snd_una ? th->rcv_nxt: dsk->sender.snd_una;
 // 		nd_clean_rtx_queue(sk);
	// 	/* add token */
 // 		dsk->grant_nxt = th->grant_nxt > dsk->grant_nxt ? th->grant_nxt : dsk->grant_nxt;
	//  	/* add sack info */
 // 		nd_get_sack_info(sk, skb);
 // 		// will be handled by nd_release_cb
 // 		test_and_set_bit(ND_CLEAN_TIMER_DEFERRED, &sk->sk_tsq_flags);
	// 	atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
	// }
	kfree_skb(skb);
	return 0;
}


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
	struct nd_sock* nsk = nd_sk(sk);
	struct sk_buff *skb, *tmp;
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
	/* handle pkts in the wait queue */
	if (flags & NDF_WAIT_DEFERRED) {
		skb_queue_walk_safe(&nsk->receiver.sk_hol_queue, skb, tmp) {
			/* this might underestimate the current buffer size if socket is handling its backlog */
			if(ND_SKB_CB(skb)->end_seq - (u32)atomic_read(&nsk->receiver.rcv_nxt) >= nd_window_size(nsk)) {
				// printk("release cb hol pkt seq:%u mem:%u rcv nxt:%u \n",ND_SKB_CB(skb)->seq, atomic_read(&sk->sk_rmem_alloc),  nsk->receiver.rcv_nxt );
				continue;
			}
			__skb_unlink(skb, &nsk->receiver.sk_hol_queue);
			/* reduce the truesize of hol_alloc of tcp socket */
			atomic_sub(skb->truesize, &tcp_sk(ND_SKB_CB(skb)->queue->sock->sk)->hol_alloc);
			atomic_sub(skb->len, &tcp_sk(ND_SKB_CB(skb)->queue->sock->sk)->hol_len);
			if(atomic_read(&tcp_sk(ND_SKB_CB(skb)->queue->sock->sk)->hol_alloc) == 0) {
				if(ndt_conn_is_latency(ND_SKB_CB(skb)->queue)) {
					queue_work_on(queue_cpu(ND_SKB_CB(skb)->queue), ndt_conn_wq_lat, &ND_SKB_CB(skb)->queue->delay_ack_work);
				} else {
					queue_work_on(queue_cpu(ND_SKB_CB(skb)->queue), ndt_conn_wq, &ND_SKB_CB(skb)->queue->delay_ack_work);
				}
				if(hrtimer_active(&ND_SKB_CB(skb)->queue->hol_timer)) {
					hrtimer_cancel(&ND_SKB_CB(skb)->queue->hol_timer);
				}
			}
			ND_SKB_CB(skb)->queue = NULL;
			nd_handle_data_skb_new(sk, skb);

			/* To Do: we might need to wake up the corresponding queue to send ack? */
			// nd_send_grant(dsk, true);
		}
		if(skb_peek(&nsk->receiver.sk_hol_queue)) {
			test_and_set_bit(ND_WAIT_DEFERRED, &sk->sk_tsq_flags);
		}

	}
	/* wake up hol channels */
	// if(flags & NDF_CHANNEL_DEFERRED) {
	// 	struct ndt_channel_entry *entry, *temp;
	// 	struct ndt_conn_queue *queue;
	// 	list_for_each_entry_safe(entry, temp, &nsk->receiver.hol_channel_list, list_link) {
	// 		queue = entry->queue;
	// 		if(ndt_conn_is_latency(queue)) {
	// 			queue_work_on(queue_cpu(queue), ndt_conn_wq_lat, &queue->io_work);
	// 		} else {
	// 			queue_work_on(queue_cpu(queue), ndt_conn_wq, &queue->io_work);
	// 		}
	// 		kfree(entry);
	// 	}
	// 	INIT_LIST_HEAD(&nsk->receiver.hol_channel_list);
	// }
	// if (flags & TCPF_MTU_REDUCED_DEFERRED) {
	// 	inet_csk(sk)->icsk_af_ops->mtu_reduced(sk);
	// 	__sock_put(sk);
	// }
}
EXPORT_SYMBOL(nd_release_cb);

/* split skb and push back the new skb into head of the queue */
int nd_split(struct sk_buff_head* queue, struct sk_buff* skb, int need_bytes) {
	struct sk_buff* new_skb;
	int bytes = ND_HEADER_MAX_SIZE, len;
	if(skb->len < need_bytes)
		return -ENOMEM;
	if(skb->len == need_bytes)
		return 0;
	/* first split new skb */
	/* this part might need to be changed */
	if(skb_headlen(skb) > need_bytes) {
		bytes +=  skb_headlen(skb) - need_bytes;
	}
	// printk("alloc bytes:%d\n", bytes);
	new_skb = alloc_skb(bytes, GFP_ATOMIC);
	if(!new_skb)
		WARN_ON(true);
	// pr_info("reach here:%d\n", __LINE__);
	// skb_dump(KERN_WARNING, skb, false);

	/* set page pool for new_skb */
	skb_shinfo(new_skb)->page_pool = skb_shinfo(skb)->page_pool;
	/* set the network header, but not tcp header */
	skb_put(new_skb, sizeof(struct iphdr));

	skb_reset_network_header(new_skb);

	memcpy(skb_network_header(new_skb), skb_network_header(skb), sizeof(struct iphdr));
	skb_pull(new_skb, sizeof(struct iphdr));
	/* change the truesize */
	len = skb->len - need_bytes;
	new_skb->truesize += len;
	skb->truesize -= len;
	skb_split(skb, new_skb, need_bytes);
	ND_SKB_CB(new_skb)->has_old_frag_list = 0;
	ND_SKB_CB(new_skb)->orig_offset = 0;
	skb_queue_head(queue, new_skb);
	// pr_info("reach here:%d\n", __LINE__);
	// skb_dump(KERN_WARNING, new_skb, false);
	return 0; 
}

/* handle the skb when they first inserted into the queue; note we have to do this in a delayed manner which allows 
	TCP to clean the cloned skbs;
*/
static void nd_queue_origin_skb(struct sk_buff_head* queue, struct sk_buff *skb) {
	struct sk_buff *list_skb, *list_skb_next, *list_skb_prev = NULL;
	if(ND_SKB_CB(skb)->orig_offset) {
		/* fraglist could change */
	 	WARN_ON(!pskb_pull(skb, ND_SKB_CB(skb)->orig_offset));
		// __skb_pull(skb, ND_SKB_CB(skb)->orig_offset);
		ND_SKB_CB(skb)->orig_offset = 0;

	}
	if(ND_SKB_CB(skb)->has_old_frag_list) {
		ND_SKB_CB(skb)->has_old_frag_list = 0;
		list_skb = skb_shinfo(skb)->frag_list;
		skb_shinfo(skb)->frag_list = NULL;
		while(list_skb) {
			if(refcount_read(&list_skb->users) > 1)
				WARN_ON(true);
			ND_SKB_CB(list_skb)->has_old_frag_list = 0;
			ND_SKB_CB(list_skb)->orig_offset = 0;
			list_skb_next = list_skb->next;
			skb->truesize -= list_skb->truesize;
			skb->data_len -= list_skb->len;
			skb->len -= list_skb->len;
			if(list_skb_prev == NULL)
				 __skb_queue_head(queue, list_skb);
			else
				__skb_queue_after(queue, list_skb_prev, list_skb);
			list_skb_prev = list_skb;
			list_skb = list_skb_next;
		}
	}

}
int nd_split_and_merge(struct sk_buff_head* queue, struct sk_buff* skb, int need_bytes, bool coalesce) {
	struct sk_buff* new_skb, *head;
	int delta = 0;
 	bool fragstolen = false;
	head = skb;
	// pr_info("reach here:%d\n", __LINE__);
	while(need_bytes > 0) {
		/* skb_split only handles non-header part */
		fragstolen = false;
		delta = 0;
		new_skb =  __skb_dequeue(queue);
		if(!new_skb)
			return -ENOMEM;
		// if(skb_cloned(new_skb))
		// 	WARN_ON(true);
		nd_queue_origin_skb(queue, new_skb);
		// pr_info("new_skb->len:%d\n", new_skb->len);
		if(new_skb->len > need_bytes)
			nd_split(queue, new_skb, need_bytes);
		need_bytes -= new_skb->len;
		// pr_info("reach here:%d\n", __LINE__);
		// pr_info("new_skb->len:%d\n", new_skb->len);
		// if(coalesce) {
		// 	if (!skb_try_coalesce(head, new_skb, &fragstolen, &delta)) {
		// 		// int i = 0;
		// 		WARN_ON(true);
		// 		// skb_dump(KERN_WARNING, head, false);
		// 		// skb_dump(KERN_WARNING, new_skb, false);
		// 		// pr_info("head has fraglist: %d\n ", skb_has_frag_list(head));
		// 		// pr_info("new_skb has fraglist: %d\n ", skb_has_frag_list(new_skb));
		// 		// pr_info("nrfragment: head:%d\n", skb_shinfo(head)->nr_frags);
		// 		// pr_info("nrfragment: new_skbhead:%d\n", skb_shinfo(new_skb)->nr_frags);
		// 		// pr_info("skb_cloned(skb):%d\n", skb_cloned(skb));
		// 		// pr_info("skb_cloned(new_skb):%d\n", skb_cloned(new_skb));
		// 		// pr_info("skb_head_is_locked:%d\n", skb_head_is_locked(new_skb));
		// 		// pr_info("Coalesce fails:%d\n", __LINE__);
		// 		// pr_info("need bytes:%d\n", need_bytes);
		// 		// pr_info("skb len:%d\n", skb->len);
		// 		// pr_info("skb trusize:%d\n", skb->truesize);
		// 		// pr_info("new skb len:%d\n", new_skb->len);
		// 		// pr_info("bew skb trusize:%d\n", new_skb->truesize);
		// 		// pr_info("skb frags:%d\n", skb_shinfo(skb)->nr_frags);
		// 		// pr_info("new skb frags:%d\n", skb_shinfo(new_skb)->nr_frags);
		// 		// for(i = 0; i <  skb_shinfo(skb)->nr_frags; i++) {
		// 		// 	skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		// 		// 	pr_info("frag %d size : %d\n ",i, skb_frag_size(frag));
		// 		// }
		// 	} else {
		// 		kfree_skb_partial(new_skb, fragstolen);
		// 	}
		// } else {
			// pr_info("reach here:%d\n", __LINE__);
			if(!skb_shinfo(head)->frag_list) {
				skb_shinfo(head)->frag_list = new_skb;
				ND_SKB_CB(head)->tail = new_skb;
				// pr_info("reach here:%d\n", __LINE__);

			} else {
				// pr_info("reach here:%d\n", __LINE__);
				if(!skb_has_frag_list(skb) || ND_SKB_CB(head)->tail == NULL)
					WARN_ON(true);
				// pr_info("!skb_has_frag_list(skb):%d\n",(!skb_has_frag_list(skb)));
                //                 pr_info("ND_SKB_CB(head)->tail:%p\n", ND_SKB_CB(head)->tail);
                //                 pr_info("ND_SKB_CB(head)->tail->next:%p\n", ND_SKB_CB(head)->tail->next);
				ND_SKB_CB(head)->tail->next = new_skb;
				ND_SKB_CB(head)->tail = new_skb;
                // pr_info("reach here:%d\n", __LINE__);

			}
			// skb = new_skb;
			/* don't increment truesize and len of head */
			// pr_info("reach here:%d\n", __LINE__);
			head->truesize += new_skb->truesize;
			head->data_len += new_skb->len;
			head->len += new_skb->len;
			ND_SKB_CB(head)->count += 1;
		// }
	}
	if(need_bytes > 0)
		return -ENOMEM;
	return 0;
}

/* reorganize skb; this part might not need to be used later*/
static void reparse_skb(struct sk_buff* skb) {
		// uint32_t count, total_len, i;
		// struct sk_buff* head = skb_shinfo(skb)->frag_list; 
		// struct iphdr *iph;
		// struct ndhdr *dh;
	
		// iph = ip_hdr(skb);
		// dh =  nd_hdr(skb);
		// /* handle the first packet which contains the header */
		// count = ND_SKB_CB(skb)->count;
		// total_len = ND_SKB_CB(skb)->total_len;

		// ND_SKB_CB(skb)->count = 0;
		// ND_SKB_CB(skb)->total_len = 0;
		// ND_SKB_CB(skb)->total_size = 0;
		// /* handle the rest of packets */
		// for(i = 0; i < count; i++) {
		// 	// WARN_ON(!head);
		// 	// head->next = NULL;
		// 	/* update the len, data_len, truesize */
		// 	skb->truesize += head->truesize;
		// 	skb->data_len += head->len;
		// 	skb->len += head->len;
		// 	head = head->next;
		// }
}

int pass_to_vs_layer(struct ndt_conn_queue *ndt_queue, struct sk_buff_head* queue) {
	struct sock *sk = ndt_queue->sock->sk;
	struct sk_buff *skb;
	struct ndhdr* nh;
	int need_bytes = 0;
	int ret;
	struct iphdr* iph;
	bool hol = false;

	// WARN_ON(queue == NULL);
	while ((skb = __skb_dequeue(queue)) != NULL) {
		// pr_info("%d skb->len:%d\n",__LINE__,  skb->len);
		// pr_info("!skb_has_frag_list(skb): %d\n", (!skb_has_frag_list(skb)));
		if(skb_cloned(skb))
			WARN_ON(true);
		nd_queue_origin_skb(queue, skb);

		// pr_info("start processing\n");
		// pr_info("skb->len:%d\n", skb->len);
		if (!pskb_may_pull(skb, sizeof(struct ndhdr))) {
			need_bytes = sizeof(struct ndhdr) - skb->len;
			if(need_bytes < 0)
				WARN_ON(true);
			// WARN_ON(need_bytes < 0);
			// pr_info("skb->len:%d\n", skb->len);
			// pr_info("reach here: %d\n", __LINE__);
			ret = nd_split_and_merge(queue, skb, need_bytes, true);
			/* No space for header . */
			if(ret == -ENOMEM) {
				goto push_back;
				// pr_info("reach here: %d\n", __LINE__);
			}
			/* pull again */
			pskb_may_pull(skb, sizeof(struct ndhdr));
		}
		// pr_info("skb->len:%d\n", skb->len);
		// pr_info("skb->headlen:%d\n", skb_headlen(skb));
		/* reset the transport layer header as nd header; and ignore TCP header */
		skb_set_transport_header(skb, 0);
		nh = nd_hdr(skb);
		// skb_dump(KERN_WARNING, skb, false);
		// WARN_ON(nh->type != DATA && nh->type != SYNC);
		/* this layer could do sort of GRO stuff later */
		if(nh->type == DATA) {
			if(!skb_has_frag_list(skb)) {
				/* first time to handle the skb */
				// skb_shinfo(head)->frag_list = NULL;
				// ND_SKB_CB(skb)->total_size = skb->truesize;
				// ND_SKB_CB(skb)->total_len = skb->len;
				ND_SKB_CB(skb)->count = 0;
				ND_SKB_CB(skb)->tail = NULL;
				
			}

			need_bytes = (int)(ntohs(nh->len)) + sizeof(struct ndhdr) - skb->len;
			// pr_info("ntohs(nh->len):%d\n", ntohs(nh->len));
			// pr_info("ND_SKB_CB(skb)->total_len:%d\n", ND_SKB_CB(skb)->total_len);
			// pr_info("LINE:%d need bytes:%d\n", __LINE__,  need_bytes);
			if(need_bytes > 0) {
				ret = nd_split_and_merge(queue, skb, need_bytes, false);
				if(ret == -ENOMEM) {
					// pr_info("go to push back\n");
					goto push_back;

				}
			}
			if(need_bytes < 0) {
				nd_split(queue, skb, ntohs(nh->len) + sizeof(struct ndhdr));
				// ND_SKB_CB(skb)->total_len += need_bytes;
			}
			/* reparse skb */
			reparse_skb(skb);
		}else {
			/* this split should always be suceessful */
			nd_split(queue, skb, sizeof(struct ndhdr));
		}
		/* pass to the vs layer; local irq should be disabled */
		// skb_dump(KERN_WARNING, skb, false);
		iph = ip_hdr(skb);
		nh = nd_hdr(skb);
		// if(nh->type == 0) {
		// 	pr_info("receive skb:%u\n", ntohl(nh->seq));
		// 	pr_info("type:%d\n", nh->type);
		// }

		// pr_info("receive new ack seq num :%u\n", ntohl(nh->grant_seq));
		// pr_info("total len:%u\n", ND_SKB_CB(skb)->total_len);
		// WARN_ON(READ_ONCE(sk->sk_rx_dst) == NULL);
		skb_dst_set_noref(skb, ndt_queue->dst);
		/* To Do: add reference count for sk in the future */
		if(nh->type == DATA)
			ND_SKB_CB(skb)->queue = ndt_queue;
		// pr_info("ND_SKB_CB(skb)->total_len:%u\n", ND_SKB_CB(skb)->total_len);
		// if(nh->type == DATA) {
		// 	pr_info("receive skb:%u CORE:%d\n", ntohl(nh->seq), raw_smp_processor_id());
		// }
		/* disable irq since it is in the process context */
		// if(nh->type == DATA) {
		// 	start_time = ktime_get_ns();
		// 	printk("receive data\n");
		// } else {
		// 	printk("receive ack\n");
		// }
		// 	pr_info("reach here:%d\n", __LINE__);
			// skb_dump(KERN_WARNING, skb, false);
		
		local_bh_disable();
		/* pass to the virutal socket layer */
		ret = nd_rcv(skb);
		/* To Do: add hrtimer if fails to adding to the socket and break the loop; */
		// if(ret == -1) {
		// 	int sdif = inet_sdif(skb);
		// 	bool refcounted = false;
		// 	struct sock *vsk;
		// 	struct nd_sock *nsk;
		// 	struct ndt_channel_entry *entry;
		// 	WARN_ON(hrtimer_active(&ndt_queue->hol_timer));
		// 	// WARN_ON(ndt_queue->hol_skb);
		// 	nh =  nd_hdr(skb);
		// 	vsk = __nd_lookup_skb(&nd_hashinfo, skb, __nd_hdrlen(nh), nh->source,
		// 			nh->dest, sdif, &refcounted);
		// 	if(unlikely(!vsk)) {
		// 		kfree_skb(skb);
		// 		goto skip_vsk;
		// 	}
		// 	nsk = nd_sk(vsk);
		// 	entry = kmalloc(sizeof(struct ndt_channel_entry), GFP_ATOMIC);
		// 	if(!entry) {
		// 		WARN_ON(true);
		// 	}
		// 	entry->queue = ndt_queue;
		// 	INIT_LIST_HEAD(&entry->list_link);
		// 	/* get socket lock */
		// 	bh_lock_sock(vsk);
		// 	list_add_tail(&entry->list_link, &nsk->receiver.hol_channel_list);
	 	// 	test_and_set_bit(ND_CHANNEL_DEFERRED, &vsk->sk_tsq_flags);
		// 	bh_unlock_sock(vsk);
		// 	/* set the state of hrtimer and hol_skb */
		// 	spin_lock(&ndt_queue->hol_lock);
		// 	ndt_queue->hol_skb = skb;
		// 	hrtimer_start(&ndt_queue->hol_timer, ns_to_ktime(ndt_queue->hol_timeout_us *
		// 		NSEC_PER_USEC), HRTIMER_MODE_REL_PINNED_SOFT);
		// 	spin_unlock(&ndt_queue->hol_lock);
		// 	hol = true;
		// 	if(refcounted)
		// 		sock_put(vsk);
		// }
skip_vsk:
		local_bh_enable();
		if(hol)
			return - 1;
		//  } else {
		// 	pr_info("finish here:%d\n", __LINE__);
		//  	kfree_skb(skb);
		//  }
	}
	return 0;
push_back:
	// printk("push back skb\n");
	skb_queue_head(queue, skb);
	return 0;
}
