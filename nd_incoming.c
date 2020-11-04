
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

/* These routines update the SACK block as out-of-order packets arrive or
 * in-order packets close up the sequence space.
 */
static void nd_sack_maybe_coalesce(struct nd_sock *dsk)
{
	int this_sack;
	struct nd_sack_block *sp = &dsk->selective_acks[0];
	struct nd_sack_block *swalk = sp + 1;

	/* See if the recent change to the first SACK eats into
	 * or hits the sequence space of other SACK blocks, if so coalesce.
	 */
	for (this_sack = 1; this_sack < dsk->num_sacks;) {
		if (nd_sack_extend(sp, swalk->start_seq, swalk->end_seq)) {
			int i;

			/* Zap SWALK, by moving every further SACK up by one slot.
			 * Decrease num_sacks.
			 */
			dsk->num_sacks--;
			for (i = this_sack; i < dsk->num_sacks; i++)
				sp[i] = sp[i + 1];
			continue;
		}
		this_sack++, swalk++;
	}
}

static void nd_sack_new_ofo_skb(struct sock *sk, u32 seq, u32 end_seq)
{
	struct nd_sock *dsk = nd_sk(sk);
	struct nd_sack_block *sp = &dsk->selective_acks[0];
	int cur_sacks = dsk->num_sacks;
	int this_sack;

	if (!cur_sacks)
		goto new_sack;

	for (this_sack = 0; this_sack < cur_sacks; this_sack++, sp++) {
		if (nd_sack_extend(sp, seq, end_seq)) {
			/* Rotate this_sack to the first one. */
			for (; this_sack > 0; this_sack--, sp--)
				swap(*sp, *(sp - 1));
			if (cur_sacks > 1)
				nd_sack_maybe_coalesce(dsk);
			return;
		}
	}

	/* Could not find an adjacent existing SACK, build a new one,
	 * put it at the front, and shift everyone else down.  We
	 * always know there is at least one SACK present already here.
	 *
	 * If the sack array is full, forget about the last one.
	 */
	if (this_sack > ND_NUM_SACKS) {
		// if (tp->compressed_ack > TCP_FASTRETRANS_THRESH)
		// 	tcp_send_ack(sk);
		WARN_ON(true);
		this_sack--;
		dsk->num_sacks--;
		sp--;
	}
	for (; this_sack > 0; this_sack--, sp--)
		*sp = *(sp - 1);

new_sack:
	/* Build the new head SACK, and we're done. */
	sp->start_seq = seq;
	sp->end_seq = end_seq;
	dsk->num_sacks++;
}

/* RCV.NXT advances, some SACKs should be eaten. */

static void nd_sack_remove(struct nd_sock *dsk)
{
	struct nd_sack_block *sp = &dsk->selective_acks[0];
	int num_sacks = dsk->num_sacks;
	int this_sack;

	/* Empty ofo queue, hence, all the SACKs are eaten. Clear. */
	if (RB_EMPTY_ROOT(&dsk->out_of_order_queue)) {
		dsk->num_sacks = 0;
		return;
	}

	for (this_sack = 0; this_sack < num_sacks;) {
		/* Check if the start of the sack is covered by RCV.NXT. */
		if (!before(dsk->receiver.rcv_nxt, sp->start_seq)) {
			int i;

			/* RCV.NXT must cover all the block! */
			WARN_ON(before(dsk->receiver.rcv_nxt, sp->end_seq));

			/* Zap this SACK, by moving forward any other SACKS. */
			for (i = this_sack+1; i < num_sacks; i++)
				dsk->selective_acks[i-1] = dsk->selective_acks[i];
			num_sacks--;
			continue;
		}
		this_sack++;
		sp++;
	}
	dsk->num_sacks = num_sacks;
}

/* read sack info */
void nd_get_sack_info(struct sock *sk, struct sk_buff *skb) {
	struct nd_sock *dsk = nd_sk(sk);
	const unsigned char *ptr = (skb_transport_header(skb) +
				    sizeof(struct nd_token_hdr));
	struct nd_token_hdr *th = nd_token_hdr(skb);
	struct nd_sack_block_wire *sp_wire = (struct nd_sack_block_wire *)(ptr);
	struct nd_sack_block *sp = dsk->selective_acks;
	// struct sk_buff *skb;
	int used_sacks;
	int i, j;
	if (!pskb_may_pull(skb, sizeof(struct nd_token_hdr) + sizeof(struct nd_sack_block_wire) * th->num_sacks)) {
		return;		/* No space for header. */
	}
	dsk->num_sacks = th->num_sacks;
	used_sacks = 0;
	for (i = 0; i < dsk->num_sacks; i++) {
		/* get_unaligned_be32 will host change the endian to be CPU order */
		sp[used_sacks].start_seq = get_unaligned_be32(&sp_wire[i].start_seq);
		sp[used_sacks].end_seq = get_unaligned_be32(&sp_wire[i].end_seq);

		used_sacks++;
	}

	/* order SACK blocks to allow in order walk of the retrans queue */
	for (i = used_sacks - 1; i > 0; i--) {
		for (j = 0; j < i; j++) {
			if (after(sp[j].start_seq, sp[j + 1].start_seq)) {
				swap(sp[j], sp[j + 1]);
			}
		}
	}
}

/* assume hold the socket spinlock*/
void nd_flow_wait_handler(struct sock *sk) {
	struct nd_sock *dsk = nd_sk(sk);
	struct rcv_core_entry *entry = &rcv_core_tab.table[dsk->core_id];

	atomic_sub(atomic_read(&dsk->receiver.in_flight_bytes), &entry->remaining_tokens);
	atomic_set(&dsk->receiver.in_flight_bytes, 0);
	dsk->receiver.flow_finish_wait = false;
	// dsk->receiver.prev_grant_bytes = 0;
	// dsk->prev_grant_nxt = dsk->grant_nxt;
	// printk("flow_wait_timer");
	// printk("entry remaining_tokens:%d\n", atomic_read(&entry->remaining_tokens));
	// printk("inet dport:%d\n",  ntohs(inet->inet_dport));
	if(test_and_clear_bit(ND_TOKEN_TIMER_DEFERRED, &sk->sk_tsq_flags)) {
		// atomic_sub(dsk->receiver.grant_batch,  &entry->remaining_tokens);
	}
	if(!dsk->receiver.finished_at_receiver)
		nd_update_and_schedule_sock(dsk);
	bh_unlock_sock(sk);
	flowlet_done_event(&entry->flowlet_done_timer);
	bh_lock_sock(sk);
}
/* ToDO: should be protected by user lock called inside softIRQ context */
enum hrtimer_restart nd_flow_wait_event(struct hrtimer *timer) {
	// struct nd_grant* grant, temp;
	struct nd_sock *dsk = container_of(timer, struct nd_sock, receiver.flow_wait_timer);
	struct sock *sk = (struct sock*)dsk;
	// struct inet_sock* inet = inet_sk(sk);
	WARN_ON(!in_softirq());
	// printk("call flow wait\n");
	bh_lock_sock(sk);
	if(!sock_owned_by_user(sk)) {
		nd_flow_wait_handler(sk);
	} else {
		test_and_set_bit(ND_WAIT_DEFERRED, &sk->sk_tsq_flags);
	}
	bh_unlock_sock(sk);
	return HRTIMER_NORESTART;
}

/* Called inside release_cb or by flow_wait_event; BH is disabled by the caller and lock_sock is hold by caller.
 * Either read buffer is limited or all toknes has been sent but some pkts are dropped.
 */
void nd_rem_check_handler(struct sock *sk) {
	// struct nd_sock* dsk = nd_sk(sk);
	// printk("handle rmem checker\n");
	// // printk("dsk->receiver.copied_seq:%u\n", dsk->receiver.copied_seq);
	// if(sk->sk_rcvbuf - atomic_read(&sk->sk_rmem_alloc) == 0) {
 //    	test_and_set_bit(ND_RMEM_CHECK_DEFERRED, &sk->sk_tsq_flags);
 //    	return;
	// }
	// /* Deadlock won't happen because flow is not in flow_q. */
	// spin_lock(&nd_epoch.lock);
	// nd_pq_push(&nd_epoch.flow_q, &dsk->match_link);
	// if(atomic_read(&nd_epoch.remaining_tokens) <= nd_params.control_pkt_bdp / 2) {
	// 	/* this part may change latter. */
	// 	hrtimer_start(&nd_epoch.token_xmit_timer, ktime_set(0, 0), HRTIMER_MODE_REL_PINNED_SOFT);
	// }
	// spin_unlock(&nd_epoch.lock);

}

void nd_token_timer_defer_handler(struct sock *sk) {
	// bool pq_empty = false;
	// int grant_bytes = calc_grant_bytes(sk);
	bool not_push_bk = false;
	struct nd_sock* dsk = nd_sk(sk);
	// struct inet_sock *inet = inet_sk(sk);
	struct rcv_core_entry *entry = &rcv_core_tab.table[dsk->core_id];
	__u32 prev_grant_nxt = dsk->prev_grant_nxt;
	// printk("timer defer handling\n");
	WARN_ON(!in_softirq());
	if(!dsk->receiver.flow_finish_wait && !dsk->receiver.finished_at_receiver) {
		int grant_bytes = calc_grant_bytes(sk);
		int rtx_bytes = rtx_bytes_count(dsk, prev_grant_nxt);
		// printk("defer grant bytes:%d\n", grant_bytes);
		if(!dsk->receiver.finished_at_receiver && (rtx_bytes != 0 || grant_bytes != 0)) {
			// printk("call timer defer xmit token\n");
			not_push_bk = xmit_batch_token(sk, grant_bytes, true);
		}
	} else {
		not_push_bk = true;
	}

	// printk("timer defer\n");
	// if(dsk->receiver.prev_grant_bytes == 0) {
	// 	int grant_bytes = calc_grant_bytes(sk);
	// 	not_push_bk = xmit_batch_token(sk, grant_bytes, true);
	// } else {
	// 	int rtx_bytes = rtx_bytes_count(dsk, prev_grant_nxt);
	// 	if(rtx_bytes && sk->sk_state == ND_RECEIVER) {
	// 		nd_xmit_control(construct_token_pkt((struct sock*)dsk, 3, prev_grant_nxt, dsk->new_grant_nxt, true),
	// 	 	dsk->peer, sk, inet->inet_dport);
	// 		atomic_add(rtx_bytes, &nd_epoch.remaining_tokens);
	// 		dsk->receiver.prev_grant_bytes += rtx_bytes;
	// 	}
	// 	if(dsk->new_grant_nxt == dsk->total_length) {
	// 		not_push_bk = true;
	// 		/* TO DO: setup a timer here */
	// 		/* current set timer to be 10 RTT */
	// 		hrtimer_start(&dsk->receiver.flow_wait_timer, ns_to_ktime(nd_params.rtt * 10 * 1000), 
	// 			HRTIMER_MODE_REL_PINNED_SOFT);
	// 	}
	// }
	/* Deadlock won't happen because flow is not in flow_q. */
	if(!not_push_bk) {
		nd_update_and_schedule_sock(dsk);
	}
	bh_unlock_sock(sk);
	flowlet_done_event(&entry->flowlet_done_timer);
	bh_lock_sock(sk);

}

void sk_stream_write_space(struct sock *sk)
{
	struct socket *sock = sk->sk_socket;
	struct socket_wq *wq;

	if (__sk_stream_is_writeable(sk, 1) && sock) {
		clear_bit(SOCK_NOSPACE, &sock->flags);

		rcu_read_lock();
		wq = rcu_dereference(sk->sk_wq);
		if (skwq_has_sleeper(wq))
			wake_up_interruptible_poll(&wq->wait, EPOLLOUT |
						EPOLLWRNORM | EPOLLWRBAND);
		if (wq && wq->fasync_list && !(sk->sk_shutdown & SEND_SHUTDOWN))
			sock_wake_async(wq, SOCK_WAKE_SPACE, POLL_OUT);
		rcu_read_unlock();
	}
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
		sk_stream_write_space(sk);
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

// check flow finished at receiver; assuming holding user lock and local bh is disabled
static void nd_check_flow_finished_at_receiver(struct nd_sock *dsk) {
	if(!dsk->receiver.finished_at_receiver && dsk->receiver.rcv_nxt == dsk->total_length) {
		struct sock* sk = (struct sock*) dsk;
		struct inet_sock *inet = inet_sk(sk);
		struct rcv_core_entry *entry = &rcv_core_tab.table[dsk->core_id];

		dsk->receiver.finished_at_receiver = true;
		if(dsk->receiver.flow_finish_wait) {
			hrtimer_cancel(&dsk->receiver.flow_wait_timer);
			test_and_clear_bit(ND_WAIT_DEFERRED, &sk->sk_tsq_flags);
			dsk->receiver.flow_finish_wait = false;
		} 
		// printk("send fin pkt\n");
		printk("dsk->in_flight:%d\n", atomic_read(&dsk->receiver.in_flight_bytes));
		printk("dentry->remaining_tokens:%d\n", atomic_read(&entry->remaining_tokens));
		atomic_sub(atomic_read(&dsk->receiver.in_flight_bytes), &entry->remaining_tokens);
		sk->sk_prot->unhash(sk);
		/* !(sk->sk_userlocks & SOCK_BINDPORT_LOCK) may need later*/
		if (nd_sk(sk)->icsk_bind_hash) {
			printk("put port\n");
			nd_put_port(sk);
		} else {
			printk("userlook and SOCK_BINDPORT_LOCK:%d\n", !(sk->sk_userlocks & SOCK_BINDPORT_LOCK));
			printk("cannot put port\n");
		}
		/* remove the socket from scheduing */
		nd_unschedule_sock(dsk);
		nd_xmit_control(construct_fin_pkt(sk), sk, inet->inet_dport); 
		if(atomic_read(&entry->remaining_tokens) <= nd_params.control_pkt_bdp / 2) {
			flowlet_done_event(&entry->flowlet_done_timer);
		}
	}

}
/* If we update dsk->receiver.rcv_nxt, also update dsk->receiver.bytes_received 
 * and send ack pkt if the flow is finished */
static void nd_rcv_nxt_update(struct nd_sock *dsk, u32 seq)
{
	struct sock *sk = (struct sock*) dsk;
	struct inet_sock *inet = inet_sk(sk);
	u32 delta = seq - dsk->receiver.rcv_nxt;
	// int grant_bytes = calc_grant_bytes(sk);

	dsk->receiver.bytes_received += delta;
	WRITE_ONCE(dsk->receiver.rcv_nxt, seq);
	// printk("update the seq:%d\n", dsk->receiver.rcv_nxt);
	if(dsk->receiver.rcv_nxt >= dsk->receiver.last_ack + dsk->receiver.max_grant_batch) {
		nd_xmit_control(construct_ack_pkt(sk, dsk->receiver.rcv_nxt), sk, inet->inet_dport); 
		dsk->receiver.last_ack = dsk->receiver.rcv_nxt;
	}
}

static void nd_drop(struct sock *sk, struct sk_buff *skb)
{
        sk_drops_add(sk, skb);
        // __kfree_skb(skb);
}

static void nd_v4_fill_cb(struct sk_buff *skb, const struct iphdr *iph,
                           const struct nd_data_hdr *dh)
{
        /* This is tricky : We move IPCB at its correct location into TCP_SKB_CB()
         * barrier() makes sure compiler wont play fool^Waliasing games.
         */
        memmove(&ND_SKB_CB(skb)->header.h4, IPCB(skb),
                sizeof(struct inet_skb_parm));
        barrier();
        ND_SKB_CB(skb)->seq = ntohl(dh->seg.offset);
        // printk("skb len:%d\n", skb->len);
        // printk("segment length:%d\n", ntohl(dh->seg.segment_length));
        ND_SKB_CB(skb)->end_seq = (ND_SKB_CB(skb)->seq + skb->len - (dh->common.doff / 4 + sizeof(struct data_segment)));
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
	int skb_truesize = from->truesize;
	*fragstolen = false;

	/* Its possible this segment overlaps with prior segment in queue */
	if (ND_SKB_CB(from)->seq != ND_SKB_CB(to)->end_seq)
		return false;

	if (!skb_try_coalesce(to, from, fragstolen, &delta))
		return false;
	/* assume we have alrady add true size beforehand*/
	atomic_sub(skb_truesize, &sk->sk_rmem_alloc);
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


static int nd_data_queue_ofo(struct sock *sk, struct sk_buff *skb)
{
	struct nd_sock *dsk = nd_sk(sk);
	struct rb_node **p, *parent;
	struct sk_buff *skb1;
	u32 seq, end_seq;
	/* Disable header prediction. */
	// tp->pred_flags = 0;
	// inet_csk_schedule_ack(sk);

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
	nd_sack_new_ofo_skb(sk, seq, end_seq);
end:
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

	p = rb_first(&dsk->out_of_order_queue);
	while (p) {
		skb = rb_to_skb(p);
		if (after(ND_SKB_CB(skb)->seq, dsk->receiver.rcv_nxt))
			break;

		// if (before(ND_SKB_CB(skb)->seq, dsack_high)) {
		// 	// __u32 dsack = dsack_high;
		// 	// if (before(TCP_SKB_CB(skb)->end_seq, dsack_high))
		// 	// 	dsack_high = TCP_SKB_CB(skb)->end_seq;
		// 	// tcp_dsack_extend(sk, TCP_SKB_CB(skb)->seq, dsack);
		// }
		p = rb_next(p);
		rb_erase(&skb->rbnode, &dsk->out_of_order_queue);

		if (unlikely(!after(ND_SKB_CB(skb)->end_seq, dsk->receiver.rcv_nxt))) {
			nd_rmem_free_skb(sk, skb);
			nd_drop(sk, skb);
			continue;
		}

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
}

void nd_data_ready(struct sock *sk)
{
        const struct nd_sock *dsk = nd_sk(sk);
        int avail = dsk->receiver.rcv_nxt - dsk->receiver.copied_seq;

        if ((avail < sk->sk_rcvlowat && dsk->receiver.rcv_nxt != dsk->total_length) && !sock_flag(sk, SOCK_DONE)) {
        	return;
        }
        sk->sk_data_ready(sk);
}

int nd_handle_flow_sync_pkt(struct sk_buff *skb) {
	// struct nd_sock *dsk;
	// struct inet_sock *inet;
	// struct nd_peer *peer;
	// struct iphdr *iph;
	// struct message_hslot* slot;
	struct nd_flow_sync_hdr *fh;
	struct sock *sk, *child;
	int sdif = inet_sdif(skb);
	bool refcounted = false;
	if (!pskb_may_pull(skb, sizeof(struct nd_flow_sync_hdr))) {
		goto drop;		/* No space for header. */
	}
	fh =  nd_flow_sync_hdr(skb);
	// sk = skb_steal_sock(skb);
	// if(!sk) {
	sk = __nd_lookup_skb(&nd_hashinfo, skb, __nd_hdrlen(&fh->common), fh->common.source,
            fh->common.dest, sdif, &refcounted);
		// sk = __nd4_lib_lookup_skb(skb, fh->common.source, fh->common.dest, &nd_table);
	// }
	if(sk) {
		child = nd_conn_request(sk, skb);
		if(child) {
			struct nd_sock *dsk = nd_sk(child);
			if(dsk->total_length >= nd_params.short_flow_size) {
				rcv_handle_new_flow(dsk);
			} else {
				/* set short flow timer */
				hrtimer_start(&dsk->receiver.flow_wait_timer, ns_to_ktime(nd_params.rtt * 1000), 
				HRTIMER_MODE_REL_PINNED_SOFT);
			}
		}
		// dsk = nd_sk(sk);
		// inet = inet_sk(sk);
		// iph = ip_hdr(skb);

		// peer = nd_peer_find(&nd_peers_table, iph->saddr, inet);
		// printk("message size:%d\n", fh->message_size);
		// msg = nd_message_in_init(peer, dsk, fh->message_id, fh->message_size, fh->common.source);
		// slot = nd_message_in_bucket(dsk, fh->message_id);
		// spin_lock_bh(&slot->lock);
		// add_nd_message_in(dsk, msg);
		// spin_unlock_bh(&slot->lock);
		// dsk->unsolved += 1;
		// printk("msg address: %p LINE:%d\n", msg, __LINE__);
		// printk("fh->message_id:%d\n", msg->id);
		// printk("fh->message_size:%d\n", msg->total_length);
		// printk("source port: %u\n", fh->common.source);
		// printk("dest port: %u\n", fh->common.dest);
		// printk("socket is NULL?: %d\n", sk == NULL);
	}


drop:
    if (refcounted) {
        sock_put(sk);
    }
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
	    	sock_rps_save_rxhash(sk, skb);
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
		xmit_handle_new_token(&xmit_core_tab, skb);
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
	struct nd_ack_hdr *ah;
	struct sock *sk;
	int sdif = inet_sdif(skb);
	bool refcounted = false;

	if (!pskb_may_pull(skb, sizeof(struct nd_ack_hdr))) {
		kfree_skb(skb);		/* No space for header. */
		return 0;
	}
	ah = nd_ack_hdr(skb);
	// sk = skb_steal_sock(skb);
	// if(!sk) {
	sk = __nd_lookup_skb(&nd_hashinfo, skb, __nd_hdrlen(&ah->common), ah->common.source,
            ah->common.dest, sdif, &refcounted);
    // }

	if(sk) {
 		bh_lock_sock(sk);
		dsk = nd_sk(sk);
		dsk->sender.snd_una = ah->rcv_nxt > dsk->sender.snd_una ? ah->rcv_nxt: dsk->sender.snd_una;
		if (!sock_owned_by_user(sk)) {
	 		nd_clean_rtx_queue(sk);
        } else {
	 		test_and_set_bit(ND_CLEAN_TIMER_DEFERRED, &sk->sk_tsq_flags);
	    }
        bh_unlock_sock(sk);
	   

		// printk("socket address: %p LINE:%d\n", dsk,  __LINE__);

	} 

    if (refcounted) {
        sock_put(sk);
    }
 	kfree_skb(skb);

	return 0;
}


// int nd_handle_sync_ack_pkt(struct sk_buff *skb) {
// 	struct nd_sock *dsk;
// 	// struct inet_sock *inet;
// 	// struct nd_peer *peer;
// 	// struct iphdr *iph;
// 	// struct ndhdr *dh;
// 	struct vs_hdr *ah;
// 	struct sock *sk;
// 	int sdif = inet_sdif(skb);
// 	bool refcounted = false;

// 	if (!pskb_may_pull(skb, sizeof(struct vs_hdr))) {
// 		kfree_skb(skb);		/* No space for header. */
// 		return 0;
// 	}
// 	ah = vs_hdr(skb);
// 	// sk = skb_steal_sock(skb);
// 	// if(!sk) {
// 	sk = __nd_lookup_skb(&nd_hashinfo, skb, __nd_hdrlen(&ah), ah->source,
//             ah->dest, sdif, &refcounted);
//     // }

//     if (refcounted) {
//         sock_put(sk);
//     }
// 	sk->sk_state = ND_SENDER;
// 	sk->sk_data_ready(sk);
//  	kfree_skb(skb);
// 	return 0;
// }

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
	if(atomic_read(&sk->sk_rmem_alloc) > sk->sk_rcvbuf) {
		struct inet_sock *inet = inet_sk(sk);
	    printk("seq num:%u\n", ND_SKB_CB(skb)->seq);
	    printk("inet sk dport:%d\n", ntohs(inet->inet_dport));
	    printk("discard packet due to memory:%d\n", __LINE__);
		sk_drops_add(sk, skb);
		kfree_skb(skb);
		return 0;
	}
	atomic_add(skb->truesize, &sk->sk_rmem_alloc);

	// skb_dst_drop(skb);
	__skb_pull(skb, (nd_hdr(skb)->doff >> 2)+ sizeof(struct data_segment));
	// printk("handle packet data queue?:%d\n", ND_SKB_CB(skb)->seq);

	/*  Queue data for delivery to the user.
	 *  Packets in sequence go to the receive queue.
	 *  Out of sequence packets to the out_of_order_queue.
	 */
	if (ND_SKB_CB(skb)->seq == dsk->receiver.rcv_nxt) {
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

		if (dsk->num_sacks)
			nd_sack_remove(dsk);

		// tcp_fast_path_check(sk);

		if (eaten > 0)
			kfree_skb_partial(skb, fragstolen);
		if (!sock_flag(sk, SOCK_DEAD)) {
			nd_data_ready(sk);
		}
		return 0;
	}
	if (!after(ND_SKB_CB(skb)->end_seq, dsk->receiver.rcv_nxt)) {
		printk("duplicate drop\n");
		printk("duplicate seq:%u\n", ND_SKB_CB(skb)->seq);
		nd_rmem_free_skb(sk, skb);
		nd_drop(sk, skb);
		return 0;
	}

	/* Out of window. F.e. zero window probe. */
	// if (!before(ND_SKB_CB(skb)->seq, dsk->rcv_nxt + tcp_receive_window(dsk)))
	// 	goto out_of_window;

	if (unlikely(before(ND_SKB_CB(skb)->seq, dsk->receiver.rcv_nxt))) {
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
		struct nd_sock *dsk = nd_sk(sk);
        u32 limit = READ_ONCE(sk->sk_rcvbuf) + READ_ONCE(sk->sk_sndbuf);
        skb_condense(skb);

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
        atomic_add(skb->truesize, &dsk->receiver.backlog_len);

        return false;

 }
/**
 * nd_data_pkt() - Handler for incoming DATA packets
 * @skb:     Incoming packet; size known to be large enough for the header.
 *           This function now owns the packet.
 * @rpc:     Information about the RPC corresponding to this packet.
 * 
 * Return: Zero means the function completed successfully. Nonzero means
 * that the RPC had to be unlocked and deleted because the socket has been
 * shut down; the caller should not access the RPC anymore. Note: this method
 * may change the RPC's state to RPC_READY.
 */
 ktime_t start,end;
 __u64 total_bytes;
int nd_handle_data_pkt(struct sk_buff *skb)
{
	struct nd_sock *dsk;
	struct nd_data_hdr *dh;
	struct sock *sk;
	struct iphdr *iph;
	int sdif = inet_sdif(skb);

	bool refcounted = false;
	bool discard = false;
	// printk("receive data pkt\n");
	if (!pskb_may_pull(skb, sizeof(struct nd_data_hdr)))
		goto drop;		/* No space for header. */
	dh =  nd_data_hdr(skb);
	// sk = skb_steal_sock(skb);
	// if(!sk) {
	sk = __nd_lookup_skb(&nd_hashinfo, skb, __nd_hdrlen(&dh->common), dh->common.source,
            dh->common.dest, sdif, &refcounted);
    if(!sk)
    	goto drop;
    // }
    // if(total_bytes == 0) {
    // 	start = ktime_get();
    // }
    // total_bytes += skb->len;
    // if(total_bytes > 300000000) {
    // 	end = ktime_get();
    // 	printk("throughput:%llu\n", total_bytes * 8 * 1000000 / ktime_to_us(ktime_sub(end, start)));
    // 	total_bytes = 0;
    // }
	nd_v4_fill_cb(skb, iph, dh);
	// printk("packet hash %u\n", skb->hash);
	// printk("oacket is l4 hash:%d\n", skb->l4_hash);
	// printk("receive packet core:%d\n", raw_smp_processor_id());
	// printk("dport:%d\n", ntohs(inet_sk(sk)->inet_dport));
	// printk("skb seq:%u\n", ND_SKB_CB(skb)->seq);
	// printk("skb address:%p\n", skb);
	if(sk && sk->sk_state == ND_RECEIVER) {
		dsk = nd_sk(sk);
		iph = ip_hdr(skb);
 		bh_lock_sock(sk);

 		atomic_sub(ND_SKB_CB(skb)->end_seq - ND_SKB_CB(skb)->seq, &dsk->receiver.in_flight_bytes);
 		if(atomic_read(&dsk->receiver.in_flight_bytes) < 0) {
 			atomic_set(&dsk->receiver.in_flight_bytes, 0);
 		}
        // ret = 0;
		// printk("atomic backlog len:%d\n", atomic_read(&dsk->receiver.backlog_len));
        if (!sock_owned_by_user(sk)) {
			/* current place to set rxhash for RFS/RPS */
			// printk("skb->hash:%u\n", skb->hash);
		 	sock_rps_save_rxhash(sk, skb);
            nd_data_queue(sk, skb);
			nd_check_flow_finished_at_receiver(dsk);;
        } else {
        	// printk("add to backlog\n");
            if (nd_add_backlog(sk, skb, false)) {
            	discard = true;
                // goto discard_and_relse;
            }
        }
        bh_unlock_sock(sk);
	} else {
		discard = true;
	}
	

	if (!dh->free_token && sk &&  sk->sk_state == ND_RECEIVER) {
		dsk = nd_sk(sk);
		int remaining_tokens = 0;
		struct rcv_core_entry *entry = &rcv_core_tab.table[dsk->core_id];
		// printk("remaining_tokens:%d\n", atomic_read(&entry->remaining_tokens));
		// printk("core id:%d\n", dsk->core_id);
		// printk("process core id:%d\n", raw_smp_processor_id());
		// printk("entry address:%p\n", entry);

		remaining_tokens = atomic_sub_return( ND_SKB_CB(skb)->end_seq - 
			ND_SKB_CB(skb)->seq, &entry->remaining_tokens);
		// if(ND_SKB_CB(skb)->end_seq == dsk->total_length) {
		// 	printk("remaining_tokens:%d\n", );
		// }

		if(remaining_tokens < 0) {
			remaining_tokens = 0;
			atomic_set(&entry->remaining_tokens, 0);
		}
		// printk("remaining_tokens variable:%d\n", remaining_tokens);
		// printk("remaining_tokens of core 15:%d\n", atomic_read(&rcv_core_tab.table[15].remaining_tokens));

		// printk("cpu core:%d\n", dsk->core_id);
		// printk("remaining_tokens:%d\n", atomic_read(&entry->remaining_tokens));
		if(atomic_read(&entry->remaining_tokens) <= nd_params.control_pkt_bdp / 2) {
			// spin_lock_bh(&entry->lock);
			// printk("call flowlet done event here:%d\n", __LINE__);
			// printk("remaining_tokens of core 15:%d\n", atomic_read(&rcv_core_tab.table[15].remaining_tokens));
			// printk("entry address:%p\n", entry);

			flowlet_done_event(&entry->flowlet_done_timer);
			// spin_unlock_bh(&entry->lock);
		}

	} 

	if (discard) {
	    printk("seq num:%u\n", ND_SKB_CB(skb)->seq);
	    printk("discard packet:%d\n", __LINE__);
		sk_drops_add(sk, skb);
	}

    if (refcounted) {
        sock_put(sk);
    }



    return 0;
drop:
    /* Discard frame. */
    kfree_skb(skb);
    return 0;

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
	dh = nd_hdr(skb);
	atomic_sub(skb->truesize, &dsk->receiver.backlog_len);
	/* current place to set rxhash for RFS/RPS */
 	sock_rps_save_rxhash(sk, skb);
	// printk("backlog rcv\n");

	if(dh->type == DATA) {
		// printk("backlog handling\n");
		nd_data_queue(sk, skb);
		// spin_lock_bh(&sk->sk_lock.slock);
		local_bh_disable();
		nd_check_flow_finished_at_receiver(dsk);
		// if(test_bit(ND_TOKEN_TIMER_DEFERRED, &sk->sk_tsq_flags)) {
		// 	printk("send token");
		// }
		local_bh_enable();
		if(!dsk->receiver.finished_at_receiver)
			nd_try_send_token(sk);

		// spin_unlock_bh(&sk->sk_lock.slock);
		if(test_bit(ND_TOKEN_TIMER_DEFERRED, &sk->sk_tsq_flags)) {
			bool push_back = false;
			struct rcv_core_entry *entry = &rcv_core_tab.table[dsk->core_id];
			// spin_lock_bh(&sk->sk_lock.slock);
			if(dsk->receiver.rcv_nxt >= dsk->prev_grant_nxt && nd_space(sk) > 0) {
				push_back = true;
				// printk("handle in backlogv\n");
				clear_bit(ND_TOKEN_TIMER_DEFERRED, &sk->sk_tsq_flags);
				local_bh_disable();
				nd_update_and_schedule_sock(dsk);
				flowlet_done_event(&entry->flowlet_done_timer);
				local_bh_enable();
			}
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
		WARN_ON(true);
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


/*
 if skb.len < len(ndhdr),
	need_bytes = len(ndhdr) - skb.len;
	goto splitAndMerge;
if skb.pktType != Data:
	if skb.len > ln(ndhdr):
		skb_split(skb, newskb, len)
		skb_queue.push_front(newskb)
	goto findskb
if skb.segmentLen > len(skb):
	need_bytes = skb.segmentLen - skb.len;
    goto splitAndMerge;

if(skb.segmentLen < len(skb)):
	skb_split(skb, newskb, sizeof(ndhdr) + segment_length);
	skb_queue.push_front(newskb);

goto findskb;
	passtovslayer(skb);
	removefromqueue(skb);
splitAndMerge:
	while(need_bytes > 0) {
		newskb = skb;
		newskb = newskb->next;
		if(skb == null)
			break;
		if(len(newskb) >= need_bytes):
			if >:
				skb_split(new_skb, nnew_skb, need_bytes);
			skb_merge(skb,new_skb);
			break;
		else:
			skb_merge(skb, new_skb) ;
			need_bytes -= len(new_skb);
	}



*/

/* split skb and push back the new skb into head of the queue */
int nd_split(struct sk_buff_head* queue, struct sk_buff* skb, int need_bytes) {
	struct sk_buff* new_skb;
	int bytes = ND_HEADER_MAX_SIZE;
	if(skb->len < need_bytes)
		return -ENOMEM;
	if(skb->len == need_bytes)
		return 0;
	/* first split new skb */
	/* this part might need to be changed */
	if(skb_headlen(skb) > need_bytes) {
		bytes +=  skb_headlen(skb) - need_bytes;
		printk("need bytes:%d\n", need_bytes);
	}
	new_skb = alloc_skb(bytes, GFP_ATOMIC);
	/* set the network header, but not tcp header */
	skb_put(new_skb, sizeof(struct iphdr));
	skb_reset_network_header(new_skb);
	memcpy(skb_network_header(new_skb), skb_network_header(skb), sizeof(struct iphdr));
	skb_pull(new_skb, sizeof(struct iphdr));
	skb_split(skb, new_skb, need_bytes);
	skb_queue_head(queue, new_skb);
	return 0; 
}

int nd_split_and_merge(struct sk_buff_head* queue, struct sk_buff* skb, int need_bytes) {
	struct sk_buff* new_skb;
	int delta = 0;
 	bool fragstolen = false;

	while(need_bytes > 0) {
		/* skb_split only handles non-header part */
		fragstolen = false;
		delta = 0;
		new_skb =  skb_dequeue(queue);
		if(!new_skb)
			return -ENOMEM;
		if(new_skb->len <= need_bytes) {
			if (!skb_try_coalesce(skb, new_skb, &fragstolen, &delta)) {
				pr_info("Coalesce fails:%d\n", __LINE__);
			} else {
				kfree_skb_partial(new_skb, fragstolen);
			}
			need_bytes -= new_skb->len;
		} else {
			pr_info("split first: %d \n", need_bytes);
			nd_split(queue, new_skb, need_bytes);
			/* then coalesce */
			if(!skb_try_coalesce(skb, new_skb,&fragstolen, &delta)) {
				pr_info("Coalesce fails:%d\n", __LINE__);
			} else {
				kfree_skb_partial(new_skb, fragstolen);
			}
			need_bytes = 0;
		}
	}
	if(need_bytes > 0)
		return -ENOMEM;
	return 0;
}
void pass_to_vs_layer(struct sock* sk, struct sk_buff_head* queue) {
	struct sk_buff *skb;
	struct ndhdr* nh;
	int need_bytes = 0;
	int ret;
	struct iphdr* iph;
	while ((skb = skb_dequeue(queue)) != NULL) {
		if (!pskb_may_pull(skb, sizeof(struct ndhdr))) {
			need_bytes = sizeof(struct ndhdr) - skb->len;
			ret = nd_split_and_merge(queue, skb, need_bytes);
			/* No space for header . */
			if(ret == -ENOMEM) {
				goto push_back;
				return;
			}
		}
		/* reset the transport layer header as nd header; and ignore TCP header */
		skb_set_transport_header(skb, 0);
		nh = nd_hdr(skb);
		/* this layer could do sort of GRO stuff later */
		if(nh->type == DATA) {
			need_bytes = nh->segment_length + sizeof(struct ndhdr) - skb->len;
			if(need_bytes > 0) {
				printk("reach here:%d\n", __LINE__);
				printk("need bytes:%d\n", need_bytes);
				printk("skb len:%d\n" , skb->len);
				ret = nd_split_and_merge(queue, skb, need_bytes);
				if(ret == -ENOMEM) {
					goto push_back;
					return;
				}
			}
			if(need_bytes < 0) {
				// printk("reach here:%d\n", __LINE__);
				// printk("need bytes:%d\n", need_bytes);
				// printk("skb len:%d\n" , skb->len);
				nd_split(queue, skb, nh->segment_length + sizeof(struct ndhdr));
			}
		}else {
			/* this split should always be suceessful */
			nd_split(queue, skb, sizeof(struct ndhdr));
		}
		/* pass to the vs layer; local irq should be disabled */
		// printk("get skb");
		// iph = ip_hdr(skb);
		// nh = nd_hdr(skb);
		// printk("skb: ip src:%d\n", iph->saddr);
		// printk("skb: ip dst:%d\n", iph->daddr);
		// printk("skb: nh type:%d\n", nh->type);
		// printk("skb: nh source:%d\n", nh->source);
		// printk("skb: nh dst:%d\n", nh->dest);
		// if(nh->type == DATA) {
		// 	printk("skb: nh segment length:%d\n", nh->segment_length);

		// }
		/* disable irq since it is in the process context */
		local_bh_disable();
		/* pass to the virutal socket layer */
		nd_rcv(skb);
		local_bh_enable();
		// kfree_skb(skb);
	}
	return;
push_back:
	printk("push back skb\n");
	skb_queue_head(queue, skb);
}