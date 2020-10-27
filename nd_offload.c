// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *	IPV4 GSO/GRO offload support
 *	Linux INET implementation
 *
 *	NDv4 GSO support
 */

#include <linux/skbuff.h>
#include <net/udp.h>
#include <net/protocol.h>
#include <net/inet_common.h>

#include "net_nd.h"


struct sk_buff *nd_gso_segment(struct sk_buff *skb,
				netdev_features_t features)
{
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	// unsigned int sum_truesize = 0;
	struct ndhdr *dh;
	// struct nd_data_hdr *data_hdr;
	unsigned int dhlen;
	unsigned int seq;
	__be32 delta;
	unsigned int oldlen;
	unsigned int mss;
	unsigned int datalen;
	// struct sk_buff *gso_skb = skb;
	// __sum16 newcheck;
	// bool ooo_okay, copy_destructor;
	dh = nd_hdr(skb);
	dhlen = dh->doff / 4;
	if (dh->type != DATA) {
		goto out;
	}
	if (dhlen < sizeof(*dh)) {
		goto out;
	}


	if (!pskb_may_pull(skb, dhlen))
		goto out;

	oldlen = (u16)~skb->len;
	datalen = ntohs(dh->len);
	__skb_pull(skb, dhlen);
	mss = skb_shinfo(skb)->gso_size;
	if (unlikely(skb->len <= mss))
		goto out;

	if (skb_gso_ok(skb, features | NETIF_F_GSO_ROBUST)) {
		/* Packet is from an untrusted source, reset gso_segs. */

		skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(skb->len, mss);

		segs = NULL;
		goto out;
	}
	// copy_destructor = gso_skb->destructor == tcp_wfree;
	// ooo_okay = gso_skb->ooo_okay;
	/* All segments but the first should have ooo_okay cleared */
	// skb->ooo_okay = 0;

	segs = skb_segment(skb, features);
	if (IS_ERR(segs))
		goto out;

	/* Only first segment might have ooo_okay set */
	// segs->ooo_okay = ooo_okay;

	/* GSO partial and frag_list segmentation only requires splitting
	 * the frame into an MSS multiple and possibly a remainder, both
	 * cases return a GSO skb. So update the mss now.
	 */
	if (skb_is_gso(segs))
		mss *= skb_shinfo(segs)->gso_segs;
	delta = htonl(oldlen + (dhlen + mss));

	skb = segs;
	dh = nd_hdr(skb);
	seq = ntohl(dh->seq);

	// if (unlikely(skb_shinfo(gso_skb)->tx_flags & SKBTX_SW_TSTAMP))
	// 	tcp_gso_tstamp(segs, skb_shinfo(gso_skb)->tskey, seq, mss);

	// newcheck = ~csum_fold((__force __wsum)((__force u32)th->check +
	// 				       (__force u32)delta));


	while (skb->next) {
		// th->fin = th->psh = 0;
		// th->check = newcheck;

		// if (skb->ip_summed == CHECKSUM_PARTIAL)
		// 	gso_reset_checksum(skb, ~th->check);
		// else
		// 	th->check = gso_make_checksum(skb, ~th->check);

		// seq += mss;
		dh->len = htons(mss);
		datalen -= mss;
		// if (copy_destructor) {
		// 	skb->destructor = gso_skb->destructor;
		// 	// skb->sk = gso_skb->sk;
		// 	// sum_truesize += skb->truesize;
		// }
		skb = skb->next;
		dh = nd_hdr(skb);

		// dh->seq = htonl(seq);
		// th->cwr = 0;

	}

	/* Following permits TCP Small Queues to work well with GSO :
	 * The callback to TCP stack will be called at the time last frag
	 * is freed at TX completion, and not right now when gso_skb
	 * is freed by GSO engine
	 */
	// if (copy_destructor) {
	// 	int delta;

	// 	swap(gso_skb->sk, skb->sk);
	// 	swap(gso_skb->destructor, skb->destructor);
	// 	sum_truesize += skb->truesize;
	// 	delta = sum_truesize - gso_skb->truesize;
	// 	 In some pathological cases, delta can be negative.
	// 	 * We need to either use refcount_add() or refcount_sub_and_test()
		 
	// 	if (likely(delta >= 0))
	// 		refcount_add(delta, &skb->sk->sk_wmem_alloc);
	// 	else
	// 		WARN_ON_ONCE(refcount_sub_and_test(-delta, &skb->sk->sk_wmem_alloc));
	// }

	// delta = htonl(oldlen + (skb_tail_pointer(skb) -
	// 			skb_transport_header(skb)) +
	// 	      skb->data_len);
	// th->check = ~csum_fold((__force __wsum)((__force u32)th->check +
	// 			(__force u32)delta));
	// if (skb->ip_summed == CHECKSUM_PARTIAL)
	// 	gso_reset_checksum(skb, ~th->check);
	// else
	// 	th->check = gso_make_checksum(skb, ~th->check);
	dh->len = htons(datalen);

out:
	return segs;
}

static struct sk_buff *nd4_gso_segment(struct sk_buff *skb,
					netdev_features_t features)
{
	if (!(skb_shinfo(skb)->gso_type & SKB_GSO_ND))
		return ERR_PTR(-EINVAL);

	if (!pskb_may_pull(skb, sizeof(struct ndhdr)))
		return ERR_PTR(-EINVAL);

	// if (unlikely(skb->ip_summed != CHECKSUM_PARTIAL)) {
	// 	const struct iphdr *iph = ip_hdr(skb);
	// 	struct tcphdr *th = tcp_hdr(skb);

	// 	 Set up checksum pseudo header, usually expect stack to
	// 	 * have done this already.
		 

	// 	th->check = 0;
	// 	skb->ip_summed = CHECKSUM_PARTIAL;
	// 	__tcp_v4_send_check(skb, iph->saddr, iph->daddr);
	// }
	return nd_gso_segment(skb, features);
}



#define ND_GRO_CNT_MAX 64

struct sk_buff *nd_gro_receive(struct list_head *head, struct sk_buff *skb)
{
	struct sk_buff *pp = NULL;
	struct sk_buff *p;
	struct ndhdr *dh;
	// struct ndhdr *dh2;
	struct nd_data_hdr *data_h;
	struct nd_data_hdr *data_h2;
	unsigned int len;
	unsigned int dhlen;
	// __be32 flags;
	unsigned int mss = 1;
	unsigned int hlen;
	unsigned int off;
	int flush = 1;
	// int i;
	off = skb_gro_offset(skb);
	hlen = off + sizeof(*dh);
	dh = skb_gro_header_fast(skb, off);
	if (skb_gro_header_hard(skb, hlen)) {
		dh = skb_gro_header_slow(skb, hlen, off);
		if (unlikely(!dh))
			goto out;
	}
	if (dh->type != DATA) {
		goto out;
	}
	dhlen = dh->doff / 4 + sizeof(struct data_segment);
	if (dhlen < sizeof(*data_h))
		goto out;

	hlen = off + dhlen;
	data_h = (struct nd_data_hdr*)dh;
	if (skb_gro_header_hard(skb, hlen)) {
		data_h = skb_gro_header_slow(skb, hlen, off);
		if (unlikely(!data_h))
			goto out;
	}
	skb_gro_pull(skb, dhlen);

	len = skb_gro_len(skb);
	// flags = tcp_flag_word(dh);
	list_for_each_entry(p, head, list) {
		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		data_h2 = nd_data_hdr(p);

		if (*(u32 *)&data_h->common.source ^ *(u32 *)&data_h2->common.source) {
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}

		goto found;
	}

	p = NULL;
	goto out_check_final;
found:
	/* Include the IP ID check below from the inner most IP hdr */
	flush = NAPI_GRO_CB(p)->flush;
// 	// flush |= 
// 	// flush |= (__force int)(flags & TCP_FLAG_CWR);
// 	// flush |= (__force int)((flags ^ tcp_flag_word(th2)) &
// 	// 	  ~(TCP_FLAG_CWR | TCP_FLAG_FIN | TCP_FLAG_PSH));
// 	// flush |= (__force int)(th->ack_seq ^ th2->ack_seq);
// 	// for (i = sizeof(*th); i < thlen; i += 4)
// 	// 	flush |= *(u32 *)((u8 *)th + i) ^
// 	// 		 *(u32 *)((u8 *)th2 + i);

// 	 When we receive our second frame we can made a decision on if we
// 	 * continue this flow as an atomic flow with a fixed ID or if we use
// 	 * an incrementing ID.
	 
	if (NAPI_GRO_CB(p)->flush_id != 1 ||
	    NAPI_GRO_CB(p)->count != 1 ||
	    !NAPI_GRO_CB(p)->is_atomic)
		flush |= NAPI_GRO_CB(p)->flush_id;
	else
		NAPI_GRO_CB(p)->is_atomic = false;

	mss = skb_shinfo(p)->gso_size;

	flush |= (len - 1) >= mss;
	flush |= (ntohl(data_h2->seg.offset) + skb_gro_len(p)) ^ ntohl(data_h->seg.offset);
#ifdef CONFIG_TLS_DEVICE
	flush |= p->decrypted ^ skb->decrypted;
#endif

	if (flush || skb_gro_receive(p, skb)) {
		mss = 1;
		goto out_check_final;
	}
// 	printk("reach here:%d\n", __LINE__);

// 	// tcp_flag_word(th2) |= flags & (TCP_FLAG_FIN | TCP_FLAG_PSH);

out_check_final:

	flush = len < mss;
	// flush |= (__force int)(flags & (TCP_FLAG_URG | TCP_FLAG_PSH |
	// 				TCP_FLAG_RST | TCP_FLAG_SYN |
	// 				TCP_FLAG_FIN));
	// printk("gro len :%d\n", skb_gro_len(p));
	if (p && (!NAPI_GRO_CB(skb)->same_flow || flush))
		pp = p;

out:
	NAPI_GRO_CB(skb)->flush |= (flush != 0);
	return pp;
}

int nd_gro_complete(struct sk_buff *skb, int dhoff)
{
	struct ndhdr *dh = nd_hdr(skb);
	// const u32 ports = (((u32)dh->source) << 16) | (__force u32)dh->dest;

	skb->csum_start = (unsigned char *)dh - skb->head;
	skb->csum_offset = offsetof(struct ndhdr, check);
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb_shinfo(skb)->gso_type |= SKB_GSO_ND;
	skb_shinfo(skb)->gso_segs = NAPI_GRO_CB(skb)->count;
	
	// printk("skb queue mapping:%d\n", skb->queue_mapping);
	// printk("old skb->hash:%d\n", skb->hash);
	// printk("l4_hash:%d\n", skb->l4_hash);
	// __skb_set_sw_hash(skb, jhash_3words(ip_hdr(skb)->saddr,
	// 	ip_hdr(skb)->daddr, ports, 0), false);
	// printk("new skb->hash:%d\n", skb->hash);
	// printk("cpu:%d\n", raw_smp_processor_id());
	// printk("gro packet core:%d\n", raw_smp_processor_id());
	// struct rps_dev_flow voidflow, *rflow = &voidflow;
	// int cpu = get_rps_cpu(skb->dev, skb, &rflow);
	// printk("rps cpu:%d\n", cpu);
	// if (th->cwr)
	// 	skb_shinfo(skb)->gso_type |= SKB_GSO_TCP_ECN;

	return 0;
}
// struct sk_buff *nd_gro_receive(struct list_head *head, struct sk_buff *skb,
// 				struct ndhdr *uh, struct sock *sk)
// {
// 	struct sk_buff *pp = NULL;
// 	struct sk_buff *p;
// 	struct ndhdr *uh2;
// 	unsigned int off = skb_gro_offset(skb);
// 	int flush = 1;

// 	if (skb->dev->features & NETIF_F_GRO_FRAGLIST)
// 		NAPI_GRO_CB(skb)->is_flist = sk ? !nd_sk(sk)->gro_enabled: 1;

// 	if ((sk && nd_sk(sk)->gro_enabled) || NAPI_GRO_CB(skb)->is_flist) {
// 		pp = call_gro_receive(nd_gro_receive_segment, head, skb);
// 		return pp;
// 	}

// 	if (!sk || NAPI_GRO_CB(skb)->encap_mark ||
// 	    (skb->ip_summed != CHECKSUM_PARTIAL &&
// 	     NAPI_GRO_CB(skb)->csum_cnt == 0 &&
// 	     !NAPI_GRO_CB(skb)->csum_valid) ||
// 	    !nd_sk(sk)->gro_receive)
// 		goto out;

// 	/* mark that this skb passed once through the tunnel gro layer */
// 	NAPI_GRO_CB(skb)->encap_mark = 1;

// 	flush = 0;

// 	list_for_each_entry(p, head, list) {
// 		if (!NAPI_GRO_CB(p)->same_flow)
// 			continue;

// 		uh2 = (struct ndhdr   *)(p->data + off);

// 		/* Match ports and either checksums are either both zero
// 		 * or nonzero.
// 		 */
// 		if ((*(u32 *)&uh->source != *(u32 *)&uh2->source) ||
// 		    (!uh->check ^ !uh2->check)) {
// 			NAPI_GRO_CB(p)->same_flow = 0;
// 			continue;
// 		}
// 	}

// 	skb_gro_pull(skb, sizeof(struct ndhdr)); /* pull encapsulating nd header */
// 	skb_gro_postpull_rcsum(skb, uh, sizeof(struct ndhdr));
// 	pp = call_gro_receive_sk(nd_sk(sk)->gro_receive, sk, head, skb);

// out:
// 	skb_gro_flush_final(skb, pp, flush);
// 	return pp;
// }
// EXPORT_SYMBOL(nd_gro_receive);

// INDIRECT_CALLABLE_SCOPE
// struct sk_buff *nd4_gro_receive(struct list_head *head, struct sk_buff *skb)
// {
// 	struct ndhdr *uh = nd_gro_ndhdr(skb);
// 	struct sk_buff *pp;
// 	struct sock *sk;

// 	if (unlikely(!uh))
// 		goto flush;

// 	/* Don't bother verifying checksum if we're going to flush anyway. */
// 	if (NAPI_GRO_CB(skb)->flush)
// 		goto skip;

// 	if (skb_gro_checksum_validate_zero_check(skb, IPPROTO_VIRTUAL_SOCK, uh->check,
// 						 inet_gro_compute_pseudo))
// 		goto flush;
// 	else if (uh->check)
// 		skb_gro_checksum_try_convert(skb, IPPROTO_VIRTUAL_SOCK,
// 					     inet_gro_compute_pseudo);
// skip:
// 	NAPI_GRO_CB(skb)->is_ipv6 = 0;
// 	rcu_read_lock();
// 	sk = static_branch_unlikely(&nd_encap_needed_key) ? nd4_lib_lookup_skb(skb, uh->source, uh->dest) : NULL;
// 	pp = nd_gro_receive(head, skb, uh, sk);
// 	rcu_read_unlock();
// 	return pp;

// flush:
// 	NAPI_GRO_CB(skb)->flush = 1;
// 	return NULL;
// }

// static int nd_gro_complete_segment(struct sk_buff *skb)
// {
// 	struct ndhdr *uh = nd_hdr(skb);

// 	skb->csum_start = (unsigned char *)uh - skb->head;
// 	skb->csum_offset = offsetof(struct ndhdr, check);
// 	skb->ip_summed = CHECKSUM_PARTIAL;

// 	skb_shinfo(skb)->gso_segs = NAPI_GRO_CB(skb)->count;
// 	skb_shinfo(skb)->gso_type |= SKB_GSO_UDP_L4;
// 	return 0;
// }

// int nd_gro_complete(struct sk_buff *skb, int nhoff,
// 		     nd_lookup_t lookup)
// {
// 	__be16 newlen = htons(skb->len - nhoff);
// 	struct ndhdr *uh = (struct ndhdr *)(skb->data + nhoff);
// 	int err = -ENOSYS;
// 	struct sock *sk;

// 	uh->len = newlen;

// 	rcu_read_lock();
// 	sk = INDIRECT_CALL_INET(lookup, udp6_lib_lookup_skb,
// 				nd4_lib_lookup_skb, skb, uh->source, uh->dest);
// 	if (sk && nd_sk(sk)->gro_complete) {
// 		skb_shinfo(skb)->gso_type = uh->check ? SKB_GSO_UDP_TUNNEL_CSUM
// 					: SKB_GSO_UDP_TUNNEL;

// 		/* Set encapsulation before calling into inner gro_complete()
// 		 * functions to make them set up the inner offsets.
// 		 */
// 		skb->encapsulation = 1;
// 		err = nd_sk(sk)->gro_complete(sk, skb,
// 				nhoff + sizeof(struct ndhdr));
// 	} else {
// 		err = nd_gro_complete_segment(skb);
// 	}
// 	rcu_read_unlock();

// 	if (skb->remcsum_offload)
// 		skb_shinfo(skb)->gso_type |= SKB_GSO_TUNNEL_REMCSUM;

// 	return err;
// }
// EXPORT_SYMBOL(nd_gro_complete);

// INDIRECT_CALLABLE_SCOPE int nd4_gro_complete(struct sk_buff *skb, int nhoff)
// {
// 	const struct iphdr *iph = ip_hdr(skb);
// 	struct ndhdr *uh = (struct ndhdr *)(skb->data + nhoff);
// 	printk("nd gro complete\n");
// 	if (NAPI_GRO_CB(skb)->is_flist) {
// 		uh->len = htons(skb->len - nhoff);

// 		skb_shinfo(skb)->gso_type |= (SKB_GSO_FRAGLIST|SKB_GSO_UDP_L4);
// 		skb_shinfo(skb)->gso_segs = NAPI_GRO_CB(skb)->count;

// 		if (skb->ip_summed == CHECKSUM_UNNECESSARY) {
// 			if (skb->csum_level < SKB_MAX_CSUM_LEVEL)
// 				skb->csum_level++;
// 		} else {
// 			skb->ip_summed = CHECKSUM_UNNECESSARY;
// 			skb->csum_level = 0;
// 		}

// 		return 0;
// 	}

// 	if (uh->check)
// 		uh->check = ~nd_v4_check(skb->len - nhoff, iph->saddr,
// 					  iph->daddr, 0);

// 	return nd_gro_complete(skb, nhoff, nd4_lib_lookup_skb);
// }

static const struct net_offload ndv4_offload = {
	.callbacks = {
		.gso_segment = nd4_gso_segment,
		.gro_receive  =	nd_gro_receive,
		.gro_complete =	nd_gro_complete,
	},
};

int __init ndv4_offload_init(void)
{
	return inet_add_offload(&ndv4_offload, IPPROTO_VIRTUAL_SOCK);
}

int ndv4_offload_end(void)
{
        return inet_del_offload(&ndv4_offload, IPPROTO_VIRTUAL_SOCK);
}
