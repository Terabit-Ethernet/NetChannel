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
#include <net/udp_tunnel.h>

// #include "linux_nd.h"
 #include "net_nd.h"
// #include "net_ndlite.h"
#include "uapi_linux_nd.h"
#include "nd_impl.h"


/* Insert buff after skb on the write or rtx queue of sk.  */
static void nd_insert_write_queue_after(struct sk_buff *skb,
					 struct sk_buff *buff,
					 struct sock *sk,
					 enum nd_queue nd_queue)
{
	if (nd_queue == ND_FRAG_IN_WRITE_QUEUE)
		skb_append(skb, buff,&sk->sk_write_queue);
	else
		nd_rbtree_insert(&sk->tcp_rtx_queue, buff);
}


/* Initialize GSO segments for a packet. */
static void nd_set_skb_gso_segs(struct sk_buff *skb, unsigned int mss_now)
{
	// if (skb->len <= mss_now) {
	// 	/* Avoid the costly divide in the normal
	// 	 * non-TSO case.
	// 	 */
	// 	tcp_skb_pcount_set(skb, 1);
	// 	TCP_SKB_CB(skb)->tcp_gso_size = 0;
	// } else {
	// 	tcp_skb_pcount_set(skb, DIV_ROUND_UP(skb->len, mss_now));
	// 	TCP_SKB_CB(skb)->tcp_gso_size = mss_now;
	// }
	if(skb->len >= mss_now) {
		skb_shinfo(skb)->gso_size = mss_now;
		skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
		// WARN_ON(skb->len != ND_SKB_CB(skb)->end_seq - ND_SKB_CB(skb)->seq);
		skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(skb->len, mss_now);

	}
}

struct sk_buff *nd_stream_alloc_skb(struct sock *sk, int size, gfp_t gfp,
				    bool force_schedule)
{
	struct sk_buff *skb;

	if (likely(!size)) {
		skb = sk->sk_tx_skb_cache;
		if (skb) {
			skb->truesize = SKB_TRUESIZE(skb_end_offset(skb));
			sk->sk_tx_skb_cache = NULL;
			pskb_trim(skb, 0);
			// INIT_LIST_HEAD(&skb->tcp_tsorted_anchor);
			skb_shinfo(skb)->tx_flags = 0;
			memset(ND_SKB_CB(skb), 0, sizeof(struct nd_skb_cb));
			return skb;
		}
	}
	/* The ND header must be at least 32-bit aligned.  */
	size = ALIGN(size, 4);

	// if (unlikely(tcp_under_memory_pressure(sk)))
	// 	sk_mem_reclaim_partial(sk);

	skb = alloc_skb_fclone(size + sk->sk_prot->max_header, gfp);
	if (likely(skb)) {
		// bool mem_scheduled;

		// if (force_schedule) {
		// 	mem_scheduled = true;
		// 	sk_forced_mem_schedule(sk, skb->truesize);
		// } else {
		// 	mem_scheduled = sk_wmem_schedule(sk, skb->truesize);
		// }
		// if (likely(mem_scheduled)) {
		// 	skb_reserve(skb, sk->sk_prot->max_header);
		// 	/*
		// 	 * Make sure that we have exactly size bytes
		// 	 * available to the caller, no more, no less.
		// 	 */
		// 	skb->reserved_tailroom = skb->end - skb->tail - size;
		// 	INIT_LIST_HEAD(&skb->tcp_tsorted_anchor);
		// 	return skb;
		// }
		// __kfree_skb(skb);
		skb_reserve(skb, sk->sk_prot->max_header);
		skb->reserved_tailroom = skb->end - skb->tail - size;
		skb->truesize = SKB_TRUESIZE(skb_end_offset(skb));

		return skb;
	} 
	// else {
	// 	sk->sk_prot->enter_memory_pressure(sk);
	// 	sk_stream_moderate_sndbuf(sk);
	// }
	// __kfree_skb(skb);
	return NULL;
}

/* assume hold bh_sock_lock */
int nd_fragment(struct sock *sk, enum nd_queue nd_queue,
		 struct sk_buff *skb, u32 len,
		 unsigned int mss_now, gfp_t gfp)
{
	// struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *buff;
	// int max_pkt_data;
	// int old_factor;
	long limit;
	int nlen;
	// u8 flags;



	if (len == 0)
		return -EINVAL;
	if (len >= skb->len)
		return -EINVAL;

	/* nd_sendmsg() can overshoot sk_wmem_queued by one full size skb.
	 * We need some allowance to not penalize applications setting small
	 * SO_SNDBUF values.
	 * Also allow first and last skb in retransmit queue to be split.
	 */
	limit = sk->sk_sndbuf + 2 * SKB_TRUESIZE(GSO_MAX_SIZE);
	if (unlikely((sk->sk_wmem_queued >> 1) > limit &&
		     nd_queue != ND_FRAG_IN_WRITE_QUEUE &&
		     skb != nd_rtx_queue_head(sk) &&
		     skb != nd_rtx_queue_tail(sk))) {
		// NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPWQUEUETOOBIG);
		return -ENOMEM;
	}

	if (skb_unclone(skb, gfp))
		return -ENOMEM;

	/* Get a new skb... force flag on. */
	buff = nd_stream_alloc_skb(sk, skb->len - len, gfp, true);
	if (!buff)
		return -ENOMEM; /* We'll just try again later. */
	skb_copy_decrypted(buff, skb);

	sk_wmem_queued_add(sk, buff->truesize);
	// sk_mem_charge(sk, buff->truesize);
	nlen = skb->len - len;
	buff->truesize += nlen;
	skb->truesize -= nlen;
	printk("do fragment\n");
	printk("new buff seq:%u\n", ND_SKB_CB(skb)->seq + len);
	/* Correct the sequence numbers. */
	ND_SKB_CB(buff)->seq = ND_SKB_CB(skb)->seq + len;
	ND_SKB_CB(buff)->end_seq = ND_SKB_CB(skb)->end_seq;
	ND_SKB_CB(skb)->end_seq = ND_SKB_CB(buff)->seq;

	/* PSH and FIN should only be set in the second packet. */
	// flags = ND_SKB_CB(skb)->tcp_flags;
	// ND_SKB_CB(skb)->tcp_flags = flags & ~(TCPHDR_FIN | TCPHDR_PSH);
	// ND_SKB_CB(buff)->tcp_flags = flags;
	// ND_SKB_CB(buff)->sacked = ND_SKB_CB(skb)->sacked;
	// tcp_skb_fragment_eor(skb, buff);
	skb_split(skb, buff, len);

	buff->ip_summed = CHECKSUM_PARTIAL;

	// buff->tstamp = skb->tstamp;
	// tcp_fragment_tstamp(skb, buff);

	// old_factor = tcp_skb_pcount(skb);

	/* Fix up tso_factor for both original and new SKB.  */
	nd_set_skb_gso_segs(skb, mss_now);
	nd_set_skb_gso_segs(buff, mss_now);

	/* Update delivered info for the new segment */
	// TCP_SKB_CB(buff)->tx = TCP_SKB_CB(skb)->tx;

	/* If this packet has been sent out already, we must
	 * adjust the various packet counters.
	 */
	// if (!before(tp->snd_nxt, TCP_SKB_CB(buff)->end_seq)) {
	// 	int diff = old_factor - tcp_skb_pcount(skb) -
	// 		tcp_skb_pcount(buff);

	// 	if (diff)
	// 		tcp_adjust_pcount(sk, skb, diff);
	// }

	/* Link BUFF into the send queue. */
	// __skb_header_release(buff);

	nd_insert_write_queue_after(skb, buff, sk, nd_queue);
	// if (tcp_queue == TCP_FRAG_IN_RTX_QUEUE)
	// 	list_add(&buff->tcp_tsorted_anchor, &skb->tcp_tsorted_anchor);

	return 0;
}
/**
 * nd_fill_packets() - Create one or more packets and fill them with
 * data from user space.
 * @homa:    Overall data about the ND protocol implementation.
 * @peer:    Peer to which the packets will be sent (needed for things like
 *           the MTU).
 * @from:    Address of the user-space source buffer.
 * @len:     Number of bytes of user data.
 * 
 * Return:   Address of the first packet in a list of packets linked through
 *           nd_next_skb, or a negative errno if there was an error. No
 *           fields are set in the packet headers except for type, incoming,
 *           offset, and length information. nd_message_out_init will fill
 *           in the other fields.
 */
int nd_fill_packets(struct sock *sk,
		struct msghdr *msg, size_t len)
{
	/* Note: this function is separate from nd_message_out_init
	 * because it must be invoked without holding an RPC lock, and
	 * nd_message_out_init must sometimes be called with the lock
	 * held.
	 */
	int bytes_left, sent_len = 0;
	struct sk_buff *skb;
	// struct sk_buff *first = NULL;
	int err, mtu, max_pkt_data, gso_size, max_gso_data;
	// struct sk_buff **last_link;
	struct dst_entry *dst;
	struct nd_sock* dsk = nd_sk(sk);
	/* check socket has enough space */
	if (unlikely(len == 0)) {
		err = -EINVAL;
		goto error;
	}

	dst = sk_dst_get(sk);
	if(dst == NULL) {
		printk("dst is NULL\n");
		return -ENOTCONN;
	}
	mtu = dst_mtu(dst);
	max_pkt_data = mtu - sizeof(struct iphdr) - sizeof(struct nd_data_hdr);
	bytes_left = len;


	if (len <= max_pkt_data ) {
		max_gso_data = len;
		gso_size = mtu;
	} else {
		int bufs_per_gso;
		
		gso_size = dst->dev->gso_max_size;
		if (gso_size > nd_params.bdp)
			gso_size = nd_params.bdp;
		// if(gso_size > nd_params.gso_size)
		// 	gso_size = nd_params.gso_size;
		/* Round gso_size down to an even # of mtus. */
		bufs_per_gso = gso_size / mtu;
		if (bufs_per_gso == 0) {
			bufs_per_gso = 1;
			mtu = gso_size;
			max_pkt_data = mtu - sizeof(struct iphdr)
					- sizeof(struct nd_data_hdr);
			WARN_ON(max_pkt_data < 0);
		}
		max_gso_data = bufs_per_gso * max_pkt_data;
		gso_size = bufs_per_gso * mtu;
		/* Round unscheduled bytes *up* to an even number of gsos. */
		// unsched = rtt_bytes + max_gso_data - 1;
		// unsched -= unsched % max_gso_data;
		// if (unsched > sent_len)
		// 	unsched = sent_len;
	}
	/* Copy message data from user space and form sk_buffs. Each
	 * sk_buff may contain multiple data_segments, each of which will
	 * turn into a separate packet, using either TSO in the NIC or
	 * GSO in software.
	 */
	// ktime_t start, end;
	// start = ktime_get();
	for (; bytes_left > 0; ) {
		// struct nd_data_hdr *h;
		struct data_segment *seg;
		int available;
		int current_len = 0;
		 // last_pkt_length;
		
		/* The sizeof(void*) creates extra space for nd_next_skb. */
		skb = nd_stream_alloc_skb(sk, gso_size, GFP_KERNEL, true);
		// if(sk->sk_tx_skb_cache != NULL) {
		// 	skb = sk->sk_tx_skb_cache;
		// 	sk->sk_tx_skb_cache = NULL;
		// } else {
		// 	skb = alloc_skb(gso_size, GFP_KERNEL);
		// }
		// skb->truesize = SKB_TRUESIZE(skb_end_offset(skb));
		/* this is a temp solution; will remove after adding split buffer mechanism */
		if (unlikely(!skb)) {
			// goto finish;
			err = -ENOMEM;
			goto error;
		}
		if (skb->truesize > sk_stream_wspace(sk) || 
			(max_gso_data > bytes_left && bytes_left + sent_len + dsk->sender.write_seq != dsk->total_length)) {
			if(!sk->sk_tx_skb_cache)
				sk->sk_tx_skb_cache = skb;
			else
				kfree_skb(skb);
			break;
		}

		// if ((bytes_left > max_pkt_data)
		// 		&& (max_gso_data > max_pkt_data)) {
		// 	skb_shinfo(skb)->gso_size = max_pkt_data;
		// 	skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
		// }
		// skb_shinfo(skb)->gso_segs = 0;

		// skb_reserve(skb, sizeof(struct iphdr));
		// skb_reset_transport_header(skb);
		// h = (struct nd_data_hdr *) skb_put(skb, sizeof(*h));
		available = max_gso_data;
		current_len = available > bytes_left? bytes_left : available;
		// h->message_id = 256;
		WRITE_ONCE(ND_SKB_CB(skb)->seq, dsk->sender.write_seq + len - bytes_left);
		WRITE_ONCE(ND_SKB_CB(skb)->end_seq, ND_SKB_CB(skb)->seq + current_len);
		// if (!copy_from_iter_full(skb_put(skb, current_len),
		// 		current_len, &msg->msg_iter)) {
		// 	err = -EFAULT;
		// 	kfree_skb(skb);
		// 	goto error;
		// }
		// skb_shinfo(skb)->gso_segs += current_len / max_pkt_data;
		// if (current_len % max_pkt_data)
		// 	skb_shinfo(skb)->gso_segs += 1;
		// bytes_left -= current_len;
		// h->common.seq = 200;
		/* Each iteration of the following loop adds one segment
		 * to the buffer.
		 */

		do {
			int seg_size;
			seg = (struct data_segment *) skb_put(skb, sizeof(*seg));
			seg->offset = htonl(len - bytes_left + dsk->sender.write_seq);

			if (bytes_left <= max_pkt_data)
				seg_size = bytes_left;
			else
				seg_size = max_pkt_data;
			seg->segment_length = htonl(seg_size);
			if (!copy_from_iter_full(skb_put(skb, seg_size),
					seg_size, &msg->msg_iter)) {
				err = -EFAULT;
				kfree_skb(skb);
				goto error;
			}
			bytes_left -= seg_size;
			// printk("seg size: %d\n", seg_size);
			// printk("offset: %d\n",  ntohl(seg->offset));
			// buffer += seg_size;
			// (skb_shinfo(skb)->gso_segs)++;
			available -= seg_size;
			// h->common.len = htons(ntohs(h->common.len) + sizeof(*seg));
		} while ((available > 0) && (bytes_left > 0));
		sent_len += current_len;
		// h->incoming = htonl(((len - bytes_left) > unsched) ?
		// 		(len - bytes_left) : unsched);
		
		/* Make sure that the last segment won't result in a
		 * packet that's too small.
		 */


		// last_pkt_length = htonl(seg->segment_length) + sizeof(*h);
		// if (unlikely(last_pkt_length < ND_HEADER_MAX_SIZE)){
		// 	skb_put(skb, ND_HEADER_MAX_SIZE - last_pkt_length);
		// }
		// *last_link = skb;
		// last_link = nd_next_skb(skb);
		// *last_link = NULL;
		nd_set_skb_gso_segs(skb, max_pkt_data + sizeof(struct data_segment));
		nd_add_write_queue_tail(sk, skb);
		sk_wmem_queued_add(sk, skb->truesize);

		// sk_mem_charge(sk, skb->truesize);
	}
		// end = ktime_get();

		// printk("time diff:%llu\n", ktime_to_us(ktime_sub(end, start)));
	// if (!sent_len) {
	// 	printk("total len:%ld\n", len);
	// 	printk("sent length:%d\n", sent_len);
	// 	printk("(sk_stream_wspace(sk):%d\n", (sk_stream_wspace(sk)));
	// }
// finish:
	WRITE_ONCE(dsk->sender.write_seq, dsk->sender.write_seq + sent_len);
	return sent_len;
	
error:
	// nd_free_skbs(first);
	return err;
}