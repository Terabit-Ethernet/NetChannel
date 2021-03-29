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
#include <net/tcp.h>
#include <linux/cpufreq.h>
#include <linux/cpumask.h> // cpumask_{first,next}(), cpu_online_mask

// #include "linux_nd.h"
// #include "net_nd.h"
// #include "net_ndlite.h"
#include "uapi_linux_nd.h"
// struct udp_table nd_table __read_mostly;
// EXPORT_SYMBOL(nd_table);
#include "nd_host.h"
#include "nd_data_copy.h"

struct nd_peertab nd_peers_table;
EXPORT_SYMBOL(nd_peers_table);

long sysctl_nd_mem[3] __read_mostly;
EXPORT_SYMBOL(sysctl_nd_mem);

atomic_long_t nd_memory_allocated;
EXPORT_SYMBOL(nd_memory_allocated);

struct nd_match_tab nd_match_table;
EXPORT_SYMBOL(nd_match_table);

struct nd_params nd_params;
EXPORT_SYMBOL(nd_params);

struct nd_epoch nd_epoch;
EXPORT_SYMBOL(nd_epoch);

struct inet_hashinfo nd_hashinfo;
EXPORT_SYMBOL(nd_hashinfo);

#define MAX_ND_PORTS 65536
#define PORTS_PER_CHAIN (MAX_ND_PORTS / ND_HTABLE_SIZE_MIN)

#define MAX_PIN_PAGES 48

static inline bool page_is_mergeable(const struct bio_vec *bv,
		struct page *page, unsigned int len, unsigned int off,
		bool *same_page)
{
	size_t bv_end = bv->bv_offset + bv->bv_len;
	phys_addr_t vec_end_addr = page_to_phys(bv->bv_page) + bv_end - 1;
	phys_addr_t page_addr = page_to_phys(page);

	if (vec_end_addr + 1 != page_addr + off)
		return false;
	// if (xen_domain() && !xen_biovec_phys_mergeable(bv, page))
	// 	return false;

	*same_page = ((vec_end_addr & PAGE_MASK) == page_addr);
	if (*same_page)
		return true;
	return (bv->bv_page + bv_end / PAGE_SIZE) == (page + off / PAGE_SIZE);
}

bool __nd_try_merge_page(struct bio_vec *bv_arr, int nr_segs,  struct page *page,
		unsigned int len, unsigned int off, bool *same_page)
{
	if (nr_segs > 0) {
		struct bio_vec *bv = &bv_arr[nr_segs - 1];

		if (page_is_mergeable(bv, page, len, off, same_page)) {
			// if (bio->bi_iter.bi_size > UINT_MAX - len) {
			// 	*same_page = false;
			// 	return false;
			// }
			bv->bv_len += len;
			return true;
		}
	}
	return false;
}

static ssize_t nd_dcopy_iov_init(struct msghdr *msg, struct iov_iter *iter, struct bio_vec *vec_p,
	u32 bytes, int max_segs) {
	ssize_t copied, offset, left;
	struct bio_vec *bv_arr;
	struct page *pages[MAX_PIN_PAGES];
	unsigned nr_segs = 0, i, len = 0;
	bool same_page = false;

	// pr_info("reach here:%d\n",  __LINE__);
	// pages = kmalloc_array(max_segs, sizeof(struct page*), GFP_KERNEL);
	// WARN_ON(pages == NULL);
	// pr_info("size of pages*:%d\n",  sizeof(struct page*));
	// *vec_p = kmalloc_array(max_segs, sizeof(struct bio_vec), GFP_KERNEL);
	// WARN_ON(*vec_p == NULL);
	bv_arr = vec_p;
	// pr_info("reach here:%d\n",  __LINE__);

	copied = iov_iter_get_pages(&msg->msg_iter, pages, bytes, max_segs,
					    &offset);
	// pr_info("reach here:%d\n",  __LINE__);
	if(copied < 0)
		WARN_ON(true);
	for (left = copied, i = 0; left > 0; left -= len, i++) {
		struct page *page = pages[i];

		len = min_t(size_t, PAGE_SIZE - offset, left);

		if (__nd_try_merge_page(bv_arr, nr_segs, page, len, offset, &same_page)) {
			if (same_page)
				put_page(page);
			// pr_info("merge page\n");
		} else {
			struct bio_vec *bv = &bv_arr[nr_segs];
			bv->bv_page = page;
			bv->bv_offset = offset;
			bv->bv_len = len;
			nr_segs++;
		}
		offset = 0;
	}
	// pr_info("advance:%ld\n", copied);
	iov_iter_bvec(iter, WRITE, bv_arr, nr_segs, copied);
	iov_iter_advance(&msg->msg_iter, copied);
	// kfree(pages);
	// pr_info("kfree:%ld\n", __LINE__);

	return copied;
}

static inline bool nd_next_segment(struct bio_vec* bv_arr,
				    struct bvec_iter_all *iter, int max_segs)
{
	/*hard code for now */
	if (iter->idx >= max_segs)
		return false;

	bvec_advance(&bv_arr[iter->idx], iter);
	return true;
}

#define nd_for_each_segment_all(bvl, bv_arr, iter, max_segs) \
	for (bvl = bvec_init_iter_all(&iter); nd_next_segment((bv_arr), &iter, max_segs); )

void nd_release_pages(struct bio_vec* bv_arr, bool mark_dirty, int max_segs)
{
	struct bvec_iter_all iter_all;
	struct bio_vec *bvec;

	nd_for_each_segment_all(bvec, bv_arr, iter_all, max_segs) {
		if (mark_dirty && !PageCompound(bvec->bv_page))
			set_page_dirty_lock(bvec->bv_page);
		put_page(bvec->bv_page);
	}
}

// u64 total_send_ack = 0;
void nd_try_send_ack(struct sock *sk, int copied) {
	struct nd_sock *nsk = nd_sk(sk);
	u32 new_grant_nxt;
	// struct inet_sock *inet = inet_sk(sk);
	if(copied > 0) {
		new_grant_nxt = nd_window_size(nsk) + nsk->receiver.rcv_nxt;
		if(new_grant_nxt - nsk->receiver.grant_nxt <= nsk->default_win && new_grant_nxt != nsk->receiver.grant_nxt && 
			new_grant_nxt - nsk->receiver.grant_nxt >= nsk->default_win / 16) {
			/* send ack pkt for new window */
			// printk("nd window size:%u\n",  nd_window_size(nsk));
			nsk->receiver.grant_nxt = new_grant_nxt;
			nd_conn_queue_request(construct_ack_req(sk, GFP_KERNEL), false, true);
			// pr_info("grant next update:%u\n", nsk->receiver.grant_nxt);
			// total_send_ack++;
		}
		// int grant_len = min_t(int, len, dsk->receiver.max_gso_data);
		// int available_space = nd_space(sk);
		// if(grant_len > available_space || grant_len < )
		// 	return;
		// printk("try to send ack \n");
	}
}

void nd_clean_dcopy_pages(struct sock *sk) {
	struct nd_sock *nsk = nd_sk(sk);
	struct nd_dcopy_page *resp;
	struct llist_node *node;
	for (node = llist_del_all(&nsk->receiver.clean_page_list); node;) {
		resp = llist_entry(node, struct nd_dcopy_page, lentry);
		node = node->next;
		if(resp->bv_arr) {
			nd_release_pages(resp->bv_arr, true, resp->max_segs);
			kfree(resp->bv_arr);
		}
		if(resp->skb){
			kfree_skb(resp->skb);
			nsk->receiver.free_skb_num += 1;
		}
		kfree(resp);
	}
	return;
}

void nd_fetch_dcopy_response(struct sock *sk) {
	struct nd_sock *nsk = nd_sk(sk);
	struct nd_dcopy_response *resp;
	struct llist_node *node;
	for (node = llist_del_all(&nsk->sender.response_list); node;) {
		resp = llist_entry(node, struct nd_dcopy_response, lentry);
		/* reuse tcp_rtx_queue due to the mess-up order */
		nd_rbtree_insert(&sk->tcp_rtx_queue, resp->skb);
		node = node->next;
		sk_wmem_queued_add(sk, resp->skb->truesize);
		sk_mem_charge(sk, resp->skb->truesize);
		nsk->sender.pending_queue -= resp->skb->len;
		WARN_ON(nsk->sender.pending_queue < 0);
		kfree(resp);
		if(nd_params.nd_debug) {
			pr_info("push seq:%d\n", ND_SKB_CB(resp->skb)->seq);
		}
	}
	return;
}

static int sk_wait_data_copy(struct sock *sk, long *timeo)
{
	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	int rc = 0;
	struct nd_sock* nsk = nd_sk(sk);
	while(atomic_read(&nsk->receiver.in_flight_copy_bytes) != 0) {
		nd_clean_dcopy_pages(sk);
		schedule();
		// schedule();
		// nd_try_send_ack(sk, 1);
		// add_wait_queue(sk_sleep(sk), &wait);
		// sk_set_bit(SOCKWQ_ASYNC_WAITDATA, sk);
		// rc = sk_wait_event(sk, timeo, atomic_read(&nsk->receiver.in_flight_copy_bytes) != 0, &wait);
		// sk_clear_bit(SOCKWQ_ASYNC_WAITDATA, sk);
		// remove_wait_queue(sk_sleep(sk), &wait);
	}
	nd_clean_dcopy_pages(sk);
	return rc;
}

static int sk_wait_sender_data_copy(struct sock *sk, long *timeo)
{
	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	int rc= 0;
	struct nd_sock* nsk = nd_sk(sk);
	while(atomic_read(&nsk->sender.in_flight_copy_bytes) != 0) {
		nd_push(sk, GFP_KERNEL);
		// nd_fetch_dcopy_response(sk);
		schedule();
		// nd_try_send_ack(sk, 1);
		// add_wait_queue(sk_sleep(sk), &wait);
		// sk_set_bit(SOCKWQ_ASYNC_WAITDATA, sk);
		// rc = sk_wait_event(sk, timeo, atomic_read(&nsk->receiver.in_flight_copy_bytes) != 0, &wait);
		// sk_clear_bit(SOCKWQ_ASYNC_WAITDATA, sk);
		// remove_wait_queue(sk_sleep(sk), &wait);
	}
	return rc;
}

void nd_rbtree_insert(struct rb_root *root, struct sk_buff *skb)
{
        struct rb_node **p = &root->rb_node;
        struct rb_node *parent = NULL;
        struct sk_buff *skb1;

        while (*p) {
                parent = *p;
                skb1 = rb_to_skb(parent);
                if (before(ND_SKB_CB(skb)->seq, ND_SKB_CB(skb1)->seq))
                        p = &parent->rb_left;
                else
                        p = &parent->rb_right;
        }
        rb_link_node(&skb->rbnode, parent, p);
        rb_insert_color(&skb->rbnode, root);
}

static void nd_rtx_queue_purge(struct sock *sk)
{
	struct rb_node *p = rb_first(&sk->tcp_rtx_queue);

	// nd_sk(sk)->highest_sack = NULL;
	while (p) {
		struct sk_buff *skb = rb_to_skb(p);

		p = rb_next(p);
		/* Since we are deleting whole queue, no need to
		 * list_del(&skb->tcp_tsorted_anchor)
		 */
		nd_rtx_queue_unlink(skb, sk);
		nd_wmem_free_skb(sk, skb);
	}
}

static void nd_ofo_queue_purge(struct sock *sk)
{
	struct nd_sock * dsk = nd_sk(sk);
	struct rb_node *p = rb_first(&dsk->out_of_order_queue);

	// nd_sk(sk)->highest_sack = NULL;
	while (p) {
		struct sk_buff *skb = rb_to_skb(p);

		p = rb_next(p);
		/* Since we are deleting whole queue, no need to
		 * list_del(&skb->tcp_tsorted_anchor)
		 */
		nd_ofo_queue_unlink(skb, sk);
		nd_rmem_free_skb(sk, skb);
	}
}

void nd_write_queue_purge(struct sock *sk)
{
	// struct nd_sock *dsk;
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&sk->sk_write_queue)) != NULL) {
		nd_wmem_free_skb(sk, skb);
	}
	nd_rtx_queue_purge(sk);
	skb = sk->sk_tx_skb_cache;
	if (skb) {
		__kfree_skb(skb);
		sk->sk_tx_skb_cache = NULL;
	}
	// sk_mem_reclaim(sk);
}

void nd_read_queue_purge(struct sock* sk) {
	struct sk_buff *skb;
	while ((skb = __skb_dequeue(&sk->sk_receive_queue)) != NULL) {
		nd_rmem_free_skb(sk, skb);
	}
	nd_ofo_queue_purge(sk);
}

int nd_err(struct sk_buff *skb, u32 info)
{
	return 0;
	// return __nd4_lib_err(skb, info, &nd_table);
}


int sk_wait_ack(struct sock *sk, long *timeo)
{
	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	int rc = 0;
	add_wait_queue(sk_sleep(sk), &wait);
	while(1) {
		if(sk->sk_state == TCP_CLOSE)
			break;
		if (signal_pending(current))
			break;
		sk_set_bit(SOCKWQ_ASYNC_WAITDATA, sk);
		rc = sk_wait_event(sk, timeo, sk->sk_state == TCP_CLOSE, &wait);
		sk_clear_bit(SOCKWQ_ASYNC_WAITDATA, sk);
	}
	remove_wait_queue(sk_sleep(sk), &wait);

	return rc;
}
EXPORT_SYMBOL(sk_wait_ack);



struct sk_buff* nd_dequeue_snd_q(struct sock *sk) {
	struct sk_buff *skb = NULL;
	struct nd_sock *nsk = nd_sk(sk);
	/* only one queue can be non-empty */
	WARN_ON(skb_peek(&sk->sk_write_queue) && rb_first(&sk->tcp_rtx_queue));
	if(skb_peek(&sk->sk_write_queue)) {
		skb = skb_peek(&sk->sk_write_queue);
		ND_SKB_CB(skb)->seq = nsk->sender.write_seq;
		nsk->sender.write_seq += skb->len;
		skb_dequeue(&sk->sk_write_queue);

	} else if(rb_first(&sk->tcp_rtx_queue)){
		struct rb_node *p = rb_first(&sk->tcp_rtx_queue);
		skb = rb_to_skb(p);
		if(nsk->sender.snd_una == ND_SKB_CB(skb)->seq) {
			nsk->sender.snd_una += skb->len;
			nd_rtx_queue_unlink(skb, sk);
		} else
			skb = NULL;
	}
	return skb;
}

bool nd_snd_q_ready(struct sock *sk) {
	struct sk_buff *skb;

	if(skb_peek(&sk->sk_write_queue)) {
		return true;
	}
	if(rb_first(&sk->tcp_rtx_queue)) {
		struct rb_node *p = rb_first(&sk->tcp_rtx_queue);
		skb = rb_to_skb(p);
		if(ND_SKB_CB(skb)->seq == nd_sk(sk)->sender.snd_nxt)
			return true;

	}
	return false;
}
int nd_push(struct sock *sk, gfp_t flag) {
	struct inet_sock *inet = inet_sk(sk);
	struct sk_buff *skb;
	struct nd_sock *nsk = nd_sk(sk);
	bool push_success;
	struct nd_conn_request* req;
	struct ndhdr* hdr;
	int ret = 0;
	u32 seq;
	
	nd_fetch_dcopy_response(sk);
	while(nd_snd_q_ready(sk) || nsk->sender.pending_req) {

		if(nsk->sender.pending_req) {
			WARN_ON(nsk->sender.pending_req == NULL);
			req = nsk->sender.pending_req;
			nsk->sender.pending_req = NULL;
			skb = req->skb;
			goto queue_req;
		}

		/* construct nd_conn_request */
		skb = nd_dequeue_snd_q(sk);
		/* out-of-order pkt */
		if(skb == NULL) {
			return  -EMSGSIZE;
		}
		req = kzalloc(sizeof(*req), flag);
		if(!req) {
			WARN_ON(true);
		}

		if(skb->len == 0 || skb->data_len == 0) {
			WARN_ON(true);
		}
		nd_init_request(sk, req);
		req->state = ND_CONN_SEND_CMD_PDU;
		// req->pdu_len = sizeof(struct ndhdr) + skb->len;
		// req->data_len = skb->len;
		hdr = req->hdr;
	// struct sk_buff* skb = __construct_control_skb(sk, 0);
	// struct nd_flow_sync_hdr* fh;
	// struct ndhdr* dh; 
	// if(unlikely(!req || !sync)) {
	// 	return -N;
	// }
	// fh = (struct nd_flow_sync_hdr *) skb_put(skb, sizeof(struct nd_flow_sync_hdr));
	
	// dh = (struct ndhdr*) (&sync->common);
		// pr_info("skb->data_len:%d\n", skb->data_len);
		// pr_info(" htons(skb->len):%d\n",  htons(skb->len));

		req->skb = skb;

		hdr->len = htons(skb->len);
		hdr->type = DATA;
		hdr->source = inet->inet_sport;
		hdr->dest = inet->inet_dport;
		// hdr->check = 0;
		hdr->doff = (sizeof(struct ndhdr)) << 2;
		hdr->seq = htonl(ND_SKB_CB(skb)->seq);
		// skb_dequeue(&sk->sk_write_queue);
			// kfree_skb(skb);
		sk_wmem_queued_add(sk, -skb->truesize);
		sk_mem_uncharge(sk, skb->truesize);
		WARN_ON(nsk->sender.snd_nxt != ND_SKB_CB(skb)->seq);
		nsk->sender.snd_nxt += skb->len;
		// if(ND_SKB_CB(skb)->seq == 0)
		// 	skb_dump(KERN_WARNING, skb, true);

		// sk->sk_wmem_queued -= skb->len;
		/*increment write seq */
		// nsk->sender.write_seq += skb->len;
queue_req:
		/* check the window is available */
		if(nsk->sender.sd_grant_nxt - (ND_SKB_CB(skb)->seq + skb->len) > nsk->default_win) {
			WARN_ON(nsk->sender.pending_req);
			// WARN_ON(nsk->sender.sd_grant_nxt - (ND_SKB_CB(skb)->seq + skb->len) < (1<<30));
			if(nd_params.nd_debug) {
				pr_info("nsk->sender.sd_grant_nxt:%u\n", nsk->sender.sd_grant_nxt);
				pr_info(" (ND_SKB_CB(skb)->seq + skb->len):%u\n",  (ND_SKB_CB(skb)->seq + skb->len));
			}
			nsk->sender.pending_req = req;
			ret = -EMSGSIZE;
			break;
		}
		seq = ND_SKB_CB(skb)->seq + skb->len;
		/* queue the request */
		push_success = nd_conn_queue_request(req, false, false);
		if(!push_success) {
			WARN_ON(nsk->sender.pending_req);
			// pr_info("add to sleep sock:%d\n", __LINE__);
			nsk->sender.pending_req = req;
			ret = -EDQUOT;
			break;
		}
		nsk->sender.snd_nxt = seq;
		// printk(" dequeue forward alloc:%d\n", sk->sk_forward_alloc);
	}
	return ret;
}

void nd_tx_work(struct work_struct *w)
{
	struct nd_sock *nsk = container_of(w, struct nd_sock, tx_work);
	struct sock *sk = (struct sock*)nsk;
	int err;
	lock_sock(sk);
	if(sk->sk_state == TCP_CLOSE) {
		 goto out;
	}
	/* Primarily for SOCK_DGRAM sockets, also handle asynchronous tx
	 * aborts
	 */
	err = nd_push(sk, GFP_KERNEL);
	/* Primarily for SOCK_SEQPACKET sockets */
	if (likely(sk->sk_socket)) {
		if(sk_stream_memory_free(sk)) {
			sk->sk_write_space(sk);
		} else if(err == -EDQUOT){
			/* push back since there is no space */
			nd_conn_add_sleep_sock(nd_ctrl, nsk);
		}
	} 	
out:
	release_sock(sk);
}

static inline bool nd_stream_memory_free(const struct sock *sk, int pending)
{
	if (READ_ONCE(sk->sk_wmem_queued) + pending >= READ_ONCE(sk->sk_sndbuf))
		return false;

	return true;
}
/* copy from kcm sendmsg */
extern struct nd_conn_ctrl* nd_ctrl;

static int nd_sender_local_dcopy(struct sock* sk, struct msghdr *msg, 
	int req_len, u32 seq, long timeo) {
	struct sk_buff *skb = NULL;
	struct nd_sock *nsk = nd_sk(sk);
	struct nd_dcopy_response *resp;
	size_t copy;
	int err, i = 0;
	while (req_len > 0) {
		bool merge = true;
		struct page_frag *pfrag = sk_page_frag(sk);
		if (!sk_page_frag_refill(sk, pfrag))
			goto wait_for_memory;
		if(!skb) 
			goto create_new_skb;
		if(skb->len == ND_MAX_SKB_LEN)
			goto push_skb;
		i = skb_shinfo(skb)->nr_frags;
		if (!skb_can_coalesce(skb, i, pfrag->page,
			 pfrag->offset)) {
			if (i == MAX_SKB_FRAGS) {
				goto push_skb;
			}
			merge = false;
		}
		copy = min_t(int, ND_MAX_SKB_LEN - skb->len, req_len);
		copy = min_t(int, copy,
			     pfrag->size - pfrag->offset);
		
		err = nd_copy_to_page_nocache(sk, &msg->msg_iter, skb,
					       pfrag->page,
					       pfrag->offset,
					       copy);
		if (err)
			goto out_error;
		/* Update the skb. */
		if (merge) {
			skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
		} else {
			skb_fill_page_desc(skb, i, pfrag->page,
					   pfrag->offset, copy);
			get_page(pfrag->page);
		}
		pfrag->offset += copy;
		req_len -= copy;
		/* last request */
		if(req_len == 0)
			goto push_skb;
		continue;

create_new_skb:
		WARN_ON(skb != NULL);
		skb = alloc_skb(0, sk->sk_allocation);
		skb->ip_summed = CHECKSUM_PARTIAL;
		// printk("create new skb\n");
		if(!skb)
			goto wait_for_memory;
		continue;

push_skb:
		/* push the new skb */
		ND_SKB_CB(skb)->seq = seq;
		resp = kmalloc(sizeof(struct nd_dcopy_response), GFP_KERNEL);
		resp->skb = skb;
		llist_add(&resp->lentry, &nsk->sender.response_list);
		seq += skb->len;
		nsk->sender.pending_queue += skb->len;

		skb = NULL;
		resp = NULL;
		continue;
wait_for_memory:
		/* wait for pending requests to be done */
		sk_wait_sender_data_copy(sk, &timeo);
		// nd_fetch_dcopy_response(sk);
		err = nd_push(sk, GFP_KERNEL);
		WARN_ON(nsk->sender.pending_queue != 0);
		// set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		/* hard code nd_ctrl for now */
		if(err == -EDQUOT){
			// pr_info("add to sleep sock send msg\n");
			nd_conn_add_sleep_sock(nd_ctrl, nsk);
		} 
		err = sk_stream_wait_memory(sk, &timeo);
		// pr_info("end wait \n");
		if (err) {
			goto out_error;
		}
	}
	return 0;
out_error:
	/* To Do: need to check whether kfree_skb should be called */
	if(skb) {
		ND_SKB_CB(skb)->seq = seq;
		resp = kmalloc(sizeof(struct nd_dcopy_response), GFP_KERNEL);
		resp->skb = skb;
		llist_add(&resp->lentry, &nsk->sender.response_list);
		seq += skb->len;
		nsk->sender.pending_queue += skb->len;
		skb = NULL;
		resp = NULL;
	}

	return err;
}

static int nd_sendmsg_new2_locked(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct nd_sock *nsk = nd_sk(sk);
	// struct sk_buff *skb = NULL;
	size_t copy, copied = 0;
	long timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
	int eor = (sk->sk_socket->type == SOCK_DGRAM) ?
		  !(msg->msg_flags & MSG_MORE) : !!(msg->msg_flags & MSG_EOR);
	int err = -EPIPE;
	// int i = 0;
	
	/* hardcode for now */
	struct nd_dcopy_request *request;
	struct iov_iter biter;
	struct bio_vec *bv_arr = NULL;
	// ssize_t bremain = msg->iter->count, blen;
	ssize_t blen;
	int max_segs = MAX_PIN_PAGES;
	int nr_segs = 0;
	// int pending = 0;
	WARN_ON(msg->msg_iter.count != len);
	if ((1 << sk->sk_state) & ~(NDF_ESTABLISH)) {
		err = nd_wait_for_connect(sk, &timeo);
		if (err != 0)
			goto out_error;
	}
	/* Per tcp_sendmsg this should be in poll */
	sk_clear_bit(SOCKWQ_ASYNC_NOSPACE, sk);

	if (sk->sk_err)
		goto out_error;

	/* intialize the nxt_dcopy_cpu */
	nsk->sender.nxt_dcopy_cpu = nd_params.data_cpy_core;

	while (msg_data_left(msg)) {

		if (!nd_stream_memory_free(sk, nsk->sender.pending_queue)) {
			// set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
			goto wait_for_memory;
		}

		/* this part might need to change latter */
		/* decide to do local or remote data copy */
		if(atomic_read(&nsk->sender.in_flight_copy_bytes) > nd_params.ldcopy_inflight_thre || 
			copied <  nd_params.ldcopy_min_thre || nd_params.nd_num_dc_thread == 0) {
			goto local_sender_copy;
		}
		copy = min_t(int, max_segs * PAGE_SIZE / ND_MAX_SKB_LEN * ND_MAX_SKB_LEN, msg_data_left(msg));
		if(copy == 0) {
			WARN_ON(true);
		}
		if (!sk_wmem_schedule(sk, copy)) {
			WARN_ON_ONCE(true);
			goto wait_for_memory;

		}
		/* remote data copy */
		/* construct biov and data copy request */
		bv_arr = kmalloc(MAX_PIN_PAGES * sizeof(struct bio_vec), GFP_KERNEL);
		blen = nd_dcopy_iov_init(msg, &biter, bv_arr, copy, max_segs);
		nr_segs = biter.nr_segs;
		nsk->sender.pending_queue += blen;

		/* create new request */
		request = kzalloc(sizeof(struct nd_dcopy_request) ,GFP_KERNEL);
		request->state = ND_DCOPY_SEND;
		request->sk = sk;
		request->io_cpu = nsk->sender.nxt_dcopy_cpu;
		request->len = blen;
		request->remain_len = blen;
		request->seq = nsk->sender.write_seq;
		request->iter = biter;
		request->bv_arr = bv_arr;
		request->max_segs = nr_segs;
		
		nd_dcopy_queue_request(request);

		bv_arr = NULL;
		nr_segs = 0;
		atomic_add(blen, &nsk->sender.in_flight_copy_bytes);
		nsk->sender.write_seq += blen;
		copied += blen;
		nsk->sender.nxt_dcopy_cpu = nd_dcopy_sche_rr(nsk->sender.nxt_dcopy_cpu);
		continue;

local_sender_copy:
		copy = min_t(int, ND_MAX_SKB_LEN, msg_data_left(msg));
		if(copy == 0) {
			WARN_ON(true);
		}
		if (!sk_wmem_schedule(sk, copy)) {
			WARN_ON_ONCE(true);
			goto wait_for_memory;

		}
		err = nd_sender_local_dcopy(sk, msg, copy, nsk->sender.write_seq, timeo);
		if(err != 0)
			goto out_error;
		nsk->sender.write_seq += copy;
		copied += copy;
		continue;
wait_for_memory:
		/* wait for pending requests to be done */
		sk_wait_sender_data_copy(sk, &timeo);
		// nd_fetch_dcopy_response(sk);
		err = nd_push(sk, GFP_KERNEL);
		WARN_ON(nsk->sender.pending_queue != 0);
		// set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		/* hard code nd_ctrl for now */
		if(err == -EDQUOT){
			// pr_info("add to sleep sock send msg\n");
			nd_conn_add_sleep_sock(nd_ctrl, nsk);
		} 
		err = sk_stream_wait_memory(sk, &timeo);
		// pr_info("end wait \n");
		if (err) {
			goto out_error;
		}
	}
	sk_wait_sender_data_copy(sk, &timeo);
	// nd_fetch_dcopy_response(sk);
	if (eor) {
		// if(!skb_queue_empty(&sk->sk_write_queue)) {
			// printk("call nd push\n");
			nd_push(sk, GFP_KERNEL);
		// }
	}

	// ND_STATS_ADD(nsk->stats.tx_bytes, copied);

	release_sock(sk);
	return copied;

out_error:
	/* wait for pending requests to be done */
	sk_wait_sender_data_copy(sk, &timeo);
	/* ToDo: might need to wait as well */
	// nd_push(sk);

	// if (copied && sock->type == SOCK_SEQPACKET) {
	// 	/* Wrote some bytes before encountering an
	// 	 * error, return partial success.
	// 	 */
	// 	goto partial_message;
	// }

	// if (head != nsk->seq_skb)
	// 	kfree_skb(head);

	err = sk_stream_error(sk, msg->msg_flags, err);

	/* make sure we wake any epoll edge trigger waiter */
	if (unlikely(skb_queue_len(&sk->sk_write_queue) == 0 && err == -EAGAIN))
		sk->sk_write_space(sk);

	return err;
}

static int nd_sendmsg_new_locked(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct nd_sock *nsk = nd_sk(sk);
	// struct sk_buff *skb = NULL;
	size_t copy, copied = 0;
	long timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
	int eor = (sk->sk_socket->type == SOCK_DGRAM) ?
		  !(msg->msg_flags & MSG_MORE) : !!(msg->msg_flags & MSG_EOR);
	int err = -EPIPE;
	// int i = 0;
	
	/* hardcode for now */
	struct nd_dcopy_request *request;
	struct iov_iter biter;
	struct bio_vec *bv_arr = NULL;
	// ssize_t bremain = msg->iter->count, blen;
	ssize_t blen;
	int max_segs = MAX_PIN_PAGES;
	int nr_segs = 0;
	// int pending = 0;
	WARN_ON(msg->msg_iter.count != len);
	if ((1 << sk->sk_state) & ~(NDF_ESTABLISH)) {
		err = nd_wait_for_connect(sk, &timeo);
		if (err != 0)
			goto out_error;
	}
	/* Per tcp_sendmsg this should be in poll */
	sk_clear_bit(SOCKWQ_ASYNC_NOSPACE, sk);

	if (sk->sk_err)
		goto out_error;
	nsk->sender.nxt_dcopy_cpu =  nd_params.data_cpy_core;
	while (msg_data_left(msg)) {

		if (!nd_stream_memory_free(sk, nsk->sender.pending_queue)) {
			// set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
			goto wait_for_memory;
		}

		/* this part might need to change latter */
		copy = min_t(int, max_segs * PAGE_SIZE / ND_MAX_SKB_LEN * ND_MAX_SKB_LEN, msg_data_left(msg));
		if(copy == 0) {
			WARN_ON(true);
		}
		if (!sk_wmem_schedule(sk, copy)) {
			WARN_ON_ONCE(true);
			goto wait_for_memory;

		}
		/* construct biov and data copy request */
		bv_arr = kmalloc(MAX_PIN_PAGES * sizeof(struct bio_vec), GFP_KERNEL);
		blen = nd_dcopy_iov_init(msg, &biter, bv_arr, copy, max_segs);
		nr_segs = biter.nr_segs;
		nsk->sender.pending_queue += blen;

		/* create new request */
		request = kzalloc(sizeof(struct nd_dcopy_request) ,GFP_KERNEL);
		request->state = ND_DCOPY_SEND;
		request->sk = sk;
		request->io_cpu = nsk->sender.nxt_dcopy_cpu;
		request->len = blen;
		request->remain_len = blen;
		request->seq = nsk->sender.write_seq;
		request->iter = biter;
		request->bv_arr = bv_arr;
		request->max_segs = nr_segs;
		
		nd_dcopy_queue_request(request);

		bv_arr = NULL;
		nr_segs = 0;
		atomic_add(blen, &nsk->sender.in_flight_copy_bytes);
		nsk->sender.write_seq += blen;

		copied += blen;
		
		nsk->sender.nxt_dcopy_cpu = nd_dcopy_sche_rr(nsk->sender.nxt_dcopy_cpu);

		continue;

wait_for_memory:
		/* wait for pending requests to be done */
		sk_wait_sender_data_copy(sk, &timeo);
		// nd_fetch_dcopy_response(sk);
		err = nd_push(sk, GFP_KERNEL);
		WARN_ON(nsk->sender.pending_queue != 0);
		// set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		/* hard code nd_ctrl for now */
		if(err == -EDQUOT){
			// pr_info("add to sleep sock send msg\n");
			nd_conn_add_sleep_sock(nd_ctrl, nsk);
		} 
		err = sk_stream_wait_memory(sk, &timeo);
		// pr_info("end wait \n");
		if (err) {
			goto out_error;
		}
	}
	sk_wait_sender_data_copy(sk, &timeo);
	// nd_fetch_dcopy_response(sk);
	if (eor) {
		// if(!skb_queue_empty(&sk->sk_write_queue)) {
			// printk("call nd push\n");
			nd_push(sk, GFP_KERNEL);
		// }
	}

	// ND_STATS_ADD(nsk->stats.tx_bytes, copied);

	release_sock(sk);
	return copied;

out_error:
	/* wait for pending requests to be done */
	sk_wait_sender_data_copy(sk, &timeo);
	/* ToDo: might need to wait as well */
	// nd_push(sk);

	// if (copied && sock->type == SOCK_SEQPACKET) {
	// 	/* Wrote some bytes before encountering an
	// 	 * error, return partial success.
	// 	 */
	// 	goto partial_message;
	// }

	// if (head != nsk->seq_skb)
	// 	kfree_skb(head);

	err = sk_stream_error(sk, msg->msg_flags, err);

	/* make sure we wake any epoll edge trigger waiter */
	if (unlikely(skb_queue_len(&sk->sk_write_queue) == 0 && err == -EAGAIN))
		sk->sk_write_space(sk);

	return err;
}

/* copy from kcm sendmsg */
static int nd_sendmsg_locked(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct nd_sock *nsk = nd_sk(sk);
	struct sk_buff *skb = NULL;
	size_t copy, copied = 0;
	long timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
	/* SOCK DGRAM? */
	// timeo = 20000;
	// printk("timeo:%ld\n", timeo);
	// printk("long max:%ld\n", LONG_MAX);
	int eor = (sk->sk_socket->type == SOCK_DGRAM) ?
		  !(msg->msg_flags & MSG_MORE) : !!(msg->msg_flags & MSG_EOR);
	int err = -EPIPE;
	int i = 0;
	
	if ((1 << sk->sk_state) & ~(NDF_ESTABLISH)) {
		err = nd_wait_for_connect(sk, &timeo);
		if (err != 0)
			goto out_error;
	}
	/* Per tcp_sendmsg this should be in poll */
	sk_clear_bit(SOCKWQ_ASYNC_NOSPACE, sk);

	if (sk->sk_err)
		goto out_error;

	while (msg_data_left(msg)) {
		bool merge = true;
		struct page_frag *pfrag = sk_page_frag(sk);
		if (!sk_page_frag_refill(sk, pfrag))
			goto wait_for_memory;
		skb = nd_write_queue_tail(sk);
		if(!skb || skb->len == ND_MAX_SKB_LEN) 
			goto create_new_skb;
		i = skb_shinfo(skb)->nr_frags;
		if (!skb_can_coalesce(skb, i, pfrag->page,
			 pfrag->offset)) {
			if (i == MAX_SKB_FRAGS) {
				goto create_new_skb;
			}
			merge = false;
		}
		copy = min_t(int, ND_MAX_SKB_LEN - skb->len, msg_data_left(msg));
		copy = min_t(int, copy,
			     pfrag->size - pfrag->offset);
		
		if(copy == 0) {
			WARN_ON(true);
			pr_info("skb->len: %d\n",skb->len);
			pr_info("msg_data_left(msg): %ld\n",msg_data_left(msg));
			pr_info("pfrag->size - pfrag->offset: %d\n", pfrag->size - pfrag->offset);

		}
		if (!sk_wmem_schedule(sk, copy))
			goto wait_for_memory;

		err = skb_copy_to_page_nocache(sk, &msg->msg_iter, skb,
					       pfrag->page,
					       pfrag->offset,
					       copy);
		if (err)
			goto out_error;
		/* Update the skb. */
		if (merge) {
			skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
		} else {
			skb_fill_page_desc(skb, i, pfrag->page,
					   pfrag->offset, copy);
			get_page(pfrag->page);
		}
		pfrag->offset += copy;
		copied += copy;

		continue;

create_new_skb:
		if (!sk_stream_memory_free(sk)) {
			// set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
			goto wait_for_memory;
		}
		skb = alloc_skb(0, sk->sk_allocation);
		// printk("create new skb\n");
		if(!skb)
			goto wait_for_memory;
		/* add truesize of skb */
		sk_wmem_queued_add(sk, skb->truesize);
		sk_mem_charge(sk, skb->truesize);
		__skb_queue_tail(&sk->sk_write_queue, skb);
		continue;


wait_for_memory:
		err = nd_push(sk, GFP_KERNEL);
		// pr_info("start wait \n");
		// pr_info("timeo:%ld\n", timeo);
		// set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		/* hard code nd_ctrl for now */
		if(err == -EDQUOT){
			// pr_info("add to sleep sock send msg\n");
			nd_conn_add_sleep_sock(nd_ctrl, nsk);
		} 
		// else {
		// 	pr_info("nsk->sender.sd_grant_nxt:%u\n", nsk->sender.sd_grant_nxt);
		// 	pr_info("nsk->sender.write_seq:%u\n", nsk->sender.write_seq);
		// }
		err = sk_stream_wait_memory(sk, &timeo);
		// pr_info("end wait \n");
		if (err) {
			pr_info("out error \n");
			goto out_error;
		}
	}
	if (eor) {
		if(!skb_queue_empty(&sk->sk_write_queue)) {
			// printk("call nd push\n");
			nd_push(sk, GFP_KERNEL);
		}
	}

	// ND_STATS_ADD(nsk->stats.tx_bytes, copied);

	release_sock(sk);
	return copied;

out_error:
	// nd_push(sk);

	// if (copied && sock->type == SOCK_SEQPACKET) {
	// 	/* Wrote some bytes before encountering an
	// 	 * error, return partial success.
	// 	 */
	// 	goto partial_message;
	// }

	// if (head != nsk->seq_skb)
	// 	kfree_skb(head);

	err = sk_stream_error(sk, msg->msg_flags, err);

	/* make sure we wake any epoll edge trigger waiter */
	if (unlikely(skb_queue_len(&sk->sk_write_queue) == 0 && err == -EAGAIN))
		sk->sk_write_space(sk);

	return err;
}

int nd_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	int ret = 0;
	lock_sock(sk);
	// nd_rps_record_flow(sk);
	ret = nd_sendmsg_new2_locked(sk, msg, len);
	release_sock(sk);
	return ret;
}
EXPORT_SYMBOL(nd_sendmsg);

int nd_sendpage(struct sock *sk, struct page *page, int offset,
		 size_t size, int flags)
{
	printk(KERN_WARNING "unimplemented sendpage invoked on nd socket\n");
	return -ENOSYS;
// 	struct inet_sock *inet = inet_sk(sk);
// 	struct nd_sock *up = nd_sk(sk);
// 	int ret;

// 	if (flags & MSG_SENDPAGE_NOTLAST)
// 		flags |= MSG_MORE;

// 	if (!up->pending) {
// 		struct msghdr msg = {	.msg_flags = flags|MSG_MORE };

// 		/* Call nd_sendmsg to specify destination address which
// 		 * sendpage interface can't pass.
// 		 * This will succeed only when the socket is connected.
// 		 */
// 		ret = nd_sendmsg(sk, &msg, 0);
// 		if (ret < 0)
// 			return ret;
// 	}

// 	lock_sock(sk);

// 	if (unlikely(!up->pending)) {
// 		release_sock(sk);

// 		net_dbg_ratelimited("cork failed\n");
// 		return -EINVAL;
// 	}

// 	ret = ip_append_page(sk, &inet->cork.fl.u.ip4,
// 			     page, offset, size, flags);
// 	if (ret == -EOPNOTSUPP) {
// 		release_sock(sk);
// 		return sock_no_sendpage(sk->sk_socket, page, offset,
// 					size, flags);
// 	}
// 	if (ret < 0) {
// 		nd_flush_pending_frames(sk);
// 		goto out;
// 	}

// 	up->len += size;
// 	if (!(up->corkflag || (flags&MSG_MORE)))
// 		ret = nd_push_pending_frames(sk);
// 	if (!ret)
// 		ret = size;
// out:
// 	release_sock(sk);
// 	return ret;
// }

// #define ND_SKB_IS_STATELESS 0x80000000

// /* all head states (dst, sk, nf conntrack) except skb extensions are
//  * cleared by nd_rcv().
//  *
//  * We need to preserve secpath, if present, to eventually process
//  * IP_CMSG_PASSSEC at recvmsg() time.
//  *
//  * Other extensions can be cleared.
//  */
// static bool nd_try_make_stateless(struct sk_buff *skb)
// {
// 	if (!skb_has_extensions(skb))
// 		return true;

// 	if (!secpath_exists(skb)) {
// 		skb_ext_reset(skb);
// 		return true;
// 	}

// 	return false;
}

/* fully reclaim rmem/fwd memory allocated for skb */
// static void nd_rmem_release(struct sock *sk, int size, int partial,
// 			     bool rx_queue_lock_held)
// {
// 	struct nd_sock *up = nd_sk(sk);
// 	struct sk_buff_head *sk_queue;
// 	int amt;

// 	if (likely(partial)) {
// 		up->forward_deficit += size;
// 		size = up->forward_deficit;
// 		if (size < (sk->sk_rcvbuf >> 2) &&
// 		    !skb_queue_empty(&up->reader_queue))
// 			return;
// 	} else {
// 		size += up->forward_deficit;
// 	}
// 	up->forward_deficit = 0;

// 	/* acquire the sk_receive_queue for fwd allocated memory scheduling,
// 	 * if the called don't held it already
// 	 */
// 	sk_queue = &sk->sk_receive_queue;
// 	if (!rx_queue_lock_held)
// 		spin_lock(&sk_queue->lock);


// 	sk->sk_forward_alloc += size;
// 	amt = (sk->sk_forward_alloc - partial) & ~(SK_MEM_QUANTUM - 1);
// 	sk->sk_forward_alloc -= amt;

// 	if (amt)
// 		__sk_mem_reduce_allocated(sk, amt >> SK_MEM_QUANTUM_SHIFT);

// 	atomic_sub(size, &sk->sk_rmem_alloc);

// 	/* this can save us from acquiring the rx queue lock on next receive */
// 	skb_queue_splice_tail_init(sk_queue, &up->reader_queue);

// 	if (!rx_queue_lock_held)
// 		spin_unlock(&sk_queue->lock);
// }

void nd_destruct_sock(struct sock *sk)
{

	/* reclaim completely the forward allocated memory */
	// unsigned int total = 0;
	struct nd_sock *nsk = nd_sk(sk);
	// struct sk_buff *skb;
	// struct udp_hslot* hslot = udp_hashslot(sk->sk_prot->h.udp_table, sock_net(sk),
	// 				     nd_sk(sk)->nd_port_hash);
	/* clean the message*/
	// skb_queue_splice_tail_init(&sk->sk_receive_queue, &dsk->reader_queue);
	// while ((skb = __skb_dequeue(&dsk->reader_queue)) != NULL) {
	// 	total += skb->truesize;
	// 	kfree_skb(skb);
	// }
	WARN_ON(nsk->sender.pending_req);
	// pr_info("0: %llu\n", bytes_recvd[0]);
	// pr_info("4: %llu\n", bytes_recvd[4]);
	// pr_info("8: %llu\n", bytes_recvd[8]);

	// pr_info("max queue length:%d\n", max_queue_length);
	// pr_info("dsk->receiver.copied_seq:%u\n", nsk->receiver.copied_seq);
	// pr_info("atomic_read(&sk->sk_rmem_alloc):%d\n", atomic_read(&sk->sk_rmem_alloc));
	// pr_info("total_send_ack:%llu\n", total_send_ack);
	// pr_info("total_send_grant:%llu\n", total_send_grant);
	/* clean sk_forward_alloc*/
	sk_mem_reclaim(sk);
	// sk->sk_forward_alloc = 0;
	// nd_rmem_release(sk, total, 0, true);
	inet_sock_destruct(sk);
	// printk("sk_memory_allocated:%ld\n", sk_memory_allocated(sk));

	/* unclear part */
	// printk("sk_memory_allocated:%ld\n", sk_memory_allocated(sk));

}
EXPORT_SYMBOL_GPL(nd_destruct_sock);

int nd_init_sock(struct sock *sk)
{
	struct nd_sock* dsk = nd_sk(sk);
	nd_set_state(sk, TCP_CLOSE);
	skb_queue_head_init(&nd_sk(sk)->reader_queue);
	dsk->core_id = raw_smp_processor_id();
	// initialize the ready queue and its lock
	sk->sk_destruct = nd_destruct_sock;
	// sk->sk_write_space = sk_stream_write_space;
	dsk->unsolved = 0;
	WRITE_ONCE(dsk->num_sacks, 0);
	INIT_WORK(&dsk->tx_work, nd_tx_work);
	WRITE_ONCE(dsk->wait_cpu, 0);
	WRITE_ONCE(dsk->wait_on_nd_conns, false);
	INIT_LIST_HEAD(&dsk->wait_list);

	/* initialize the sndbuf and rcvbuf */
	WRITE_ONCE(sk->sk_sndbuf, nd_params.wmem_default);
	WRITE_ONCE(sk->sk_rcvbuf, nd_params.rmem_default);
	WRITE_ONCE(dsk->default_win , min_t(uint32_t, nd_params.bdp, READ_ONCE(sk->sk_rcvbuf)));

	// INIT_LIST_HEAD(&dsk->match_link);
	WRITE_ONCE(dsk->sender.write_seq, 0);
	WRITE_ONCE(dsk->sender.snd_nxt, 0);
	WRITE_ONCE(dsk->sender.snd_una, 0);
	WRITE_ONCE(dsk->sender.pending_req, NULL);
	WRITE_ONCE(dsk->sender.nxt_dcopy_cpu, -1);	
	WRITE_ONCE(dsk->sender.pending_queue, 0);
    init_llist_head(&dsk->sender.response_list);
	WRITE_ONCE(dsk->sender.sd_grant_nxt, dsk->default_win);

	WRITE_ONCE(dsk->receiver.rcv_nxt, 0);
	WRITE_ONCE(dsk->receiver.last_ack, 0);
	WRITE_ONCE(dsk->receiver.copied_seq, 0);
	WRITE_ONCE(dsk->receiver.grant_nxt, dsk->default_win);
	WRITE_ONCE(dsk->receiver.nxt_dcopy_cpu, nd_params.data_cpy_core);
	WRITE_ONCE(dsk->receiver.rmem_exhausted, 0);
	WRITE_ONCE(dsk->receiver.prev_grant_bytes, 0);

	atomic_set(&dsk->receiver.in_flight_copy_bytes, 0);
	dsk->receiver.free_skb_num = 0;
	init_llist_head(&dsk->receiver.clean_page_list);


	kfree_skb(sk->sk_tx_skb_cache);
	sk->sk_tx_skb_cache = NULL;
	/* reuse tcp rtx queue*/
	sk->tcp_rtx_queue = RB_ROOT;
	dsk->out_of_order_queue = RB_ROOT;
	// printk("flow wait at init:%d\n", dsk->receiver.flow_wait);
	return 0;
}
EXPORT_SYMBOL_GPL(nd_init_sock);

/*
 *	IOCTL requests applicable to the ND protocol
 */

int nd_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
	printk(KERN_WARNING "unimplemented ioctl invoked on ND socket\n");
	return -ENOSYS;
}
EXPORT_SYMBOL(nd_ioctl);

bool nd_try_send_token(struct sock *sk) {
	// if(test_bit(ND_TOKEN_TIMER_DEFERRED, &sk->sk_tsq_flags)) {
	// 	// struct nd_sock *dsk = nd_sk(sk);
	// 	// int grant_len = min_t(int, len, dsk->receiver.max_gso_data);
	// 	// int available_space = nd_space(sk);
	// 	// if(grant_len > available_space || grant_len < )
	// 	// 	return;
	// 	// printk("try to send token \n");
	// 	int grant_bytes = calc_grant_bytes(sk);

	// 	// printk("grant bytes delay:%d\n", grant_bytes);
	// 	if (grant_bytes > 0) {
	// 		// spin_lock_bh(&sk->sk_lock.slock);
	// 		xmit_batch_token(sk, grant_bytes, false);
	// 		// spin_unlock_bh(&sk->sk_lock.slock);
	// 		return true;
	// 	}
	// }
	return false;

}



int nd_recvmsg_new(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
		int flags, int *addr_len)
{

	struct nd_sock *dsk = nd_sk(sk);
	int copied = 0;
	// u32 peek_seq;
	u32 *seq;
	unsigned long used;
	int err;
	// int inq;
	int target;		/* Read at least this many bytes */
	long timeo;
	// int trigger_tokens = 1;
	struct sk_buff *skb, *last, *tmp;
	struct nd_dcopy_request *request;
	// u32 urg_hole = 0;
	// struct scm_timestamping_internal tss;
	// int cmsg_flags;
	// printk("recvmsg start \n");
	// printk("rcvmsg core:%d\n", raw_smp_processor_id());
	
	/* hardcode for now */ 
	// struct page *bpages[48];
	// struct bio_vec bvec;
	struct iov_iter biter;
	struct bio_vec *bv_arr;
	ssize_t bremain = len, blen;
	int max_segs = MAX_PIN_PAGES;
	int nr_segs = 0;
	int qid;
	// printk("convert bytes:%ld\n", ret);

	// nd_rps_record_flow(sk);
	WARN_ON(atomic_read(&dsk->receiver.in_flight_copy_bytes) != 0);
	WARN_ON(!llist_empty(&dsk->receiver.clean_page_list));
	// if (unlikely(flags & MSG_ERRQUEUE))
	// 	return inet_recv_error(sk, msg, len, addr_len);
	// printk("start recvmsg \n");
	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);

	// printk("target bytes:%d\n", target);

	if (sk_can_busy_loop(sk) && skb_queue_empty_lockless(&sk->sk_receive_queue) &&
	    (sk->sk_state == ND_ESTABLISH))
		sk_busy_loop(sk, nonblock);

	lock_sock(sk);
	err = -ENOTCONN;


	// cmsg_flags = tp->recvmsg_inq ? 1 : 0;
	timeo = sock_rcvtimeo(sk, nonblock);

	if (sk->sk_state != ND_ESTABLISH)
		goto out;

	/* init bvec page */	
	bv_arr = kmalloc(MAX_PIN_PAGES * sizeof(struct bio_vec), GFP_KERNEL);
	blen = nd_dcopy_iov_init(msg, &biter, bv_arr,  bremain, max_segs);
	nr_segs = biter.nr_segs;
	bremain -= blen;



	seq = &dsk->receiver.copied_seq;
	dsk->receiver.nxt_dcopy_cpu = nd_params.data_cpy_core;
	// printk("start queue\n");
	do {
		u32 offset;
		/* Next get a buffer. */

		last = skb_peek_tail(&sk->sk_receive_queue);
		skb_queue_walk_safe(&sk->sk_receive_queue, skb, tmp) {
			last = skb;

			/* Now that we have two receive queues this
			 * shouldn't happen.
			 */
			if (WARN(before(*seq, ND_SKB_CB(skb)->seq),
				 "ND recvmsg seq # bug: copied %X, seq %X, rcvnxt %X, fl %X\n",
				 *seq, ND_SKB_CB(skb)->seq, dsk->receiver.rcv_nxt,
				 flags))
				break;

			offset = *seq - ND_SKB_CB(skb)->seq;

			if (offset < skb->len) {
				goto found_ok_skb; 
			}
			else {
				WARN_ON(true);
			}
		}


		/* ToDo: we have to check whether pending requests are done */
		/* Well, if we have backlog, try to process it now yet. */

		if (copied >= target && !READ_ONCE(sk->sk_backlog.tail)) {
			break;
		}

		if (copied) {
			if (sk->sk_err ||
			    sk->sk_state == TCP_CLOSE ||
			    (sk->sk_shutdown & RCV_SHUTDOWN) ||
			    !timeo ||
			    signal_pending(current))
				break;
		} else {
			if (sock_flag(sk, SOCK_DONE))
				break;

			if (sk->sk_err) {
				copied = sock_error(sk);
				break;
			}

			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;

			if (sk->sk_state == TCP_CLOSE) {
				/* This occurs when user tries to read
				 * from never connected socket.
				 */
				copied = -ENOTCONN;
				break;
			}

			if (!timeo) {
				copied = -EAGAIN;
				break;
			}

			if (signal_pending(current)) {
				copied = sock_intr_errno(timeo);
				break;
			}
		}

		// tcp_cleanup_rbuf(sk, copied);
		nd_try_send_ack(sk, copied);
		// printk("release sock");
		if (copied >= target) {
			/* Do not sleep, just process backlog. */
			/* Release sock will handle the backlog */
			release_sock(sk);
			lock_sock(sk);
		} else {
			sk_wait_data(sk, &timeo, last);
		}

		continue;

found_ok_skb:
		/* Ok so how much can we use? */
		used = skb->len - offset;
		
		// if(blen == 0) {
		// 	// pr_info("free bvec bv page:%d\n", __LINE__);
		// 	// pr_info("biter.bvec->bv_page:%p\n", bv_arr->bv_page);
		// 	// kfree(bv_arr);
		// 	// pr_info("done:%d\n", __LINE__);
		// 	// bv_arr = NULL;
		// 	sk_wait_data_copy(sk, &timeo);
		// 	nd_release_pages(bv_arr, true, nr_segs);
		// 	kfree(bv_arr);
		// }
		if(blen < used)
			used = blen;

		if (len < used) {
			WARN_ON(true);
			used = len;
		}

        // unsigned cpu = cpumask_first(cpu_online_mask);

        // while (cpu < nr_cpu_ids) {
        //         pr_info("CPU: %u, freq: %u kHz\n", cpu, cpufreq_get(cpu));
        //         cpu = cpumask_next(cpu, cpu_online_mask);
        // }
		/* construct data copy request */
		request = kzalloc(sizeof(struct nd_dcopy_request) ,GFP_KERNEL);
		request->state = ND_DCOPY_RECV;
		request->sk = sk;
		request->clean_skb = (used + offset == skb->len);
		request->io_cpu = dsk->receiver.nxt_dcopy_cpu;
		request->skb = skb;
		request->offset = offset;
		request->len = used;
		request->remain_len = used;
		// dup_iter(&request->iter, &biter, GFP_KERNEL);
		request->iter = biter;
		// printk("cpu:%d req bytes:%d skb bytes:%d frags:%d\n", request->io_cpu,  request->len, skb->len, skb_shinfo(skb)->nr_frags);
		// bytes_recvd[request->io_cpu] += request->len;
		// pr_info("request:%p\n", request);
		// pr_info("sizeof(struct nd_dcopy_request):%d\n", sizeof(struct nd_dcopy_request));
		// request->iter = msg->msg_iter;
		// pr_info("request->len: %d\n", request->len);
		/* update the biter */
		iov_iter_advance(&biter, used);
		blen -= used;

		if(blen == 0) {
			request->bv_arr = bv_arr;
			request->max_segs = nr_segs;
			bv_arr = NULL;
			nr_segs = 0;
		}
		// if (!(flags & MSG_TRUNC)) {
		// 	err = skb_copy_datagram_msg(skb, offset, msg, used);
		// 	// printk("copy data done: %d\n", used);
		// 	if (err) {
		// 		/* Exception. Bailout! */
		// 		if (!copied)
		// 			copied = -EFAULT;
		// 		break;
		// 	}
		// }

		WRITE_ONCE(*seq, *seq + used);
		copied += used;
		len -= used;
		if (used + offset < skb->len)
			goto queue_request;
		// pr_info("copied_seq:%d\n", seq);
		WARN_ON(used + offset > skb->len);
		__skb_unlink(skb, &sk->sk_receive_queue);
		// atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
		// kfree_skb(skb);

queue_request:
		atomic_add(used, &dsk->receiver.in_flight_copy_bytes);
		/* queue the data copy request */
		// pr_info("old msg->msg_iter.iov_base:%p\n", msg->msg_iter.iov->iov_base);
		// pr_info("old msg->msg_iter.iov_len:%ld\n", msg->msg_iter.iov->iov_len);
		
		qid = nd_dcopy_queue_request(request);
		// pr_info("queue request:%d, skb->len:%d req->len:%d \n", qid, skb->len, request->len);

		// if(dsk->receiver.nxt_dcopy_cpu == -1) {
		// 	dsk->receiver.nxt_dcopy_cpu = qid;
		// 	// printk("new qid:%d\n", qid);
		// }
		if(blen == 0 && bremain > 0) {
			ssize_t bsize = bremain;
			if(used + offset < skb->len) {
				bsize =  min_t(ssize_t, bsize, skb->len - offset - used);
			} else {
				dsk->receiver.nxt_dcopy_cpu = nd_dcopy_sche_rr(dsk->receiver.nxt_dcopy_cpu);
			}
			bv_arr = kmalloc(MAX_PIN_PAGES * sizeof(struct bio_vec), GFP_KERNEL);
			blen = nd_dcopy_iov_init(msg, &biter, bv_arr, bsize, max_segs);
			nr_segs = biter.nr_segs;
			bremain -= blen;
			// sk_wait_data_copy(sk, &timeo);
		}
		// pr_info("skb_headlen(skb):%d\n", skb_headlen(skb));
		// pr_info("start wait \n");
		// sk_wait_data_copy(sk, &timeo);
		// pr_info("finish wait \n");

		// dsk->receiver.nxt_dcopy_cpu = (dsk->receiver.nxt_dcopy_cpu + 4) % 32;
		// if(dsk->receiver.nxt_dcopy_cpu == 0)
		// 	dsk->receiver.nxt_dcopy_cpu = 4;
		// pr_info("msg->msg_iter.count:%ld\n", msg->msg_iter.count);
		// pr_info("msg->msg_iter.iov_offset:%ld\n", msg->msg_iter.iov_offset);
		// iov_iter_advance(&msg->msg_iter, used);
		// pr_info("advance \n");
		continue;

		// if (copied > 3 * trigger_tokens * dsk->receiver.max_gso_data) {
		// 	// nd_try_send_token(sk);
		// 	trigger_tokens += 1;
			
		// }
		// nd_try_send_token(sk);

		// tcp_rcv_space_adjust(sk);

// skip_copy:
		// if (tp->urg_data && after(tp->copied_seq, tp->urg_seq)) {
		// 	tp->urg_data = 0;
		// 	tcp_fast_path_check(sk);
		// }
		// if (used + offset < skb->len)
		// 	continue;

		// if (TCP_SKB_CB(skb)->has_rxtstamp) {
		// 	tcp_update_recv_tstamps(skb, &tss);
		// 	cmsg_flags |= 2;
		// }
		// if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
		// 	goto found_fin_ok;
		// if (!(flags & MSG_PEEK))
		// 	sk_eat_skb(sk, skb);
		// continue;

// found_fin_ok:
		/* Process the FIN. */
		// WRITE_ONCE(*seq, *seq + 1);
		// if (!(flags & MSG_PEEK))
		// 	sk_eat_skb(sk, skb);
		// break;
	} while (len > 0);
	
	/* free the bvec memory */


	/* According to UNIX98, msg_name/msg_namelen are ignored
	 * on connected socket. I was just happy when found this 8) --ANK
	 */
	 	/* waiting data copy to be finishede */
	// while(atomic_read(&nsk->receiver.in_flight_copy_bytes) != 0) {
	// printk("start wait\n");
	sk_wait_data_copy(sk, &timeo);
	if(bv_arr) {
		nd_release_pages(bv_arr, true, nr_segs);
		kfree(bv_arr);
	}
	// pr_info("free bvec:%d\n", __LINE__);
	// pr_info("biter.bvec:%p\n", biter.bvec);
	// nd_release_pages(bv_arr, true, nr_segs);
	// kfree(bv_arr);
	// }
	/* Clean up data we have read: This will do ACK frames. */
	// tcp_cleanup_rbuf(sk, copied);
	nd_try_send_ack(sk, copied);
	// if (dsk->receiver.copied_seq == dsk->total_length) {
	// 	printk("call tcp close in the recv msg\n");
	// 	nd_set_state(sk, TCP_CLOSE);
	// } else {
	// 	// nd_try_send_token(sk);
	// }
	release_sock(sk);
	// printk("return");
	// if (cmsg_flags) {
	// 	if (cmsg_flags & 2)
	// 		tcp_recv_timestamp(msg, sk, &tss);
	// 	if (cmsg_flags & 1) {
	// 		inq = tcp_inq_hint(sk);
	// 		put_cmsg(msg, SOL_TCP, TCP_CM_INQ, sizeof(inq), &inq);
	// 	}
	// }
	// printk("recvmsg\n");

	return copied;

out:
	release_sock(sk);
	return err;

// recv_urg:
// 	err = tcp_recv_urg(sk, msg, len, flags);
// 	goto out;

// recv_sndq:
// 	// err = tcp_peek_sndq(sk, msg, len);
// 	goto out;
}

int nd_recvmsg_new_2(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
		int flags, int *addr_len)
{

	struct nd_sock *dsk = nd_sk(sk);
	int copied = 0;
	// u32 peek_seq;
	u32 *seq;
	unsigned long used;
	int err;
	int target;		/* Read at least this many bytes */
	long timeo;
	struct sk_buff *skb, *last, *tmp;
	struct nd_dcopy_request *request;

	
	/* hardcode for now */ 
	struct iov_iter biter;
	struct bio_vec *bv_arr = NULL;
	ssize_t blen = 0;
	int max_segs = MAX_PIN_PAGES;
	int nr_segs = 0;
	int qid;
	bool in_remote_cpy;
	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);

	if (sk_can_busy_loop(sk) && skb_queue_empty_lockless(&sk->sk_receive_queue) &&
	    (sk->sk_state == ND_ESTABLISH))
		sk_busy_loop(sk, nonblock);

	lock_sock(sk);
	err = -ENOTCONN;


	// cmsg_flags = tp->recvmsg_inq ? 1 : 0;
	timeo = sock_rcvtimeo(sk, nonblock);

	if (sk->sk_state != ND_ESTABLISH)
		goto out;

	/* init bvec page */	
	// bv_arr = kmalloc(MAX_PIN_PAGES * sizeof(struct bio_vec), GFP_KERNEL);
	// blen = nd_dcopy_iov_init(msg, &biter, bv_arr,  bremain, max_segs);
	// nr_segs = biter.nr_segs;
	// bremain -= blen;
	
	/* set nxt_dcopy_cpu to be -1 */
	in_remote_cpy = false;
	dsk->receiver.nxt_dcopy_cpu = nd_params.data_cpy_core;

	seq = &dsk->receiver.copied_seq;
	do {
		u32 offset;
		/* Next get a buffer. */

		last = skb_peek_tail(&sk->sk_receive_queue);
		skb_queue_walk_safe(&sk->sk_receive_queue, skb, tmp) {
			last = skb;

			/* Now that we have two receive queues this
			 * shouldn't happen.
			 */
			if (WARN(before(*seq, ND_SKB_CB(skb)->seq),
				 "ND recvmsg seq # bug: copied %X, seq %X, rcvnxt %X, fl %X\n",
				 *seq, ND_SKB_CB(skb)->seq, dsk->receiver.rcv_nxt,
				 flags))
				break;

			offset = *seq - ND_SKB_CB(skb)->seq;

			if (offset < skb->len) {
				goto found_ok_skb; 
			}
			else {
				WARN_ON(true);
			}
		}


		/* ToDo: we have to check whether pending requests are done */
		/* Well, if we have backlog, try to process it now yet. */

		if (copied >= target && !READ_ONCE(sk->sk_backlog.tail))
			break;

		if (copied) {
			if (sk->sk_err ||
			    sk->sk_state == TCP_CLOSE ||
			    (sk->sk_shutdown & RCV_SHUTDOWN) ||
			    !timeo ||
			    signal_pending(current))
				break;
		} else {
			if (sock_flag(sk, SOCK_DONE))
				break;

			if (sk->sk_err) {
				copied = sock_error(sk);
				break;
			}

			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;

			if (sk->sk_state == TCP_CLOSE) {
				/* This occurs when user tries to read
				 * from never connected socket.
				 */
				copied = -ENOTCONN;
				break;
			}

			if (!timeo) {
				copied = -EAGAIN;
				break;
			}

			if (signal_pending(current)) {
				copied = sock_intr_errno(timeo);
				break;
			}
		}

		// tcp_cleanup_rbuf(sk, copied);
		nd_try_send_ack(sk, copied);
		// printk("release sock");
		if (copied >= target) {
			/* Do not sleep, just process backlog. */
			/* Release sock will handle the backlog */
			release_sock(sk);
			lock_sock(sk);
		} else {
			sk_wait_data(sk, &timeo, last);
		}

		continue;

found_ok_skb:
		/* Ok so how much can we use? */
		used = skb->len - offset;

		if (len < used) {
			used = len;
		}
		/* decide to do local or remote data copy*/
		if(blen == 0) {
			ssize_t bsize = len;
			/* the same skb can either do local or remote but not both */
			if(in_remote_cpy && offset != 0) {
				bsize =  min_t(ssize_t, bsize, used);
				goto pin_user_page;
			}

			/* check the current CPU util */
			if(atomic_read(&dsk->receiver.in_flight_copy_bytes) > nd_params.ldcopy_inflight_thre || 
				copied <  nd_params.ldcopy_min_thre || nd_params.nd_num_dc_thread == 0){
				/* do local */
				in_remote_cpy = false;
				goto local_copy;
			}
			/* set up the remote data copy core and state */
			in_remote_cpy = true;
			dsk->receiver.nxt_dcopy_cpu = nd_dcopy_sche_rr(dsk->receiver.nxt_dcopy_cpu);
			
			// printk("dsk->receiver.nxt_dcopy_cpu:%d\n", dsk->receiver.nxt_dcopy_cpu);
pin_user_page:
			bv_arr = kmalloc(MAX_PIN_PAGES * sizeof(struct bio_vec), GFP_KERNEL);
			blen = nd_dcopy_iov_init(msg, &biter, bv_arr, bsize, max_segs);
			nr_segs = biter.nr_segs;
		} 

		if(!in_remote_cpy || blen == 0) {
			WARN_ON_ONCE(true);
			goto local_copy;
		}
		
		/* do remote data copy */
		if(blen < used && blen > 0)
			used = blen;
		/* construct data copy request */
		request = kzalloc(sizeof(struct nd_dcopy_request) ,GFP_KERNEL);
		request->state = ND_DCOPY_RECV;
		request->sk = sk;
		request->clean_skb = (used + offset == skb->len);
		request->io_cpu = dsk->receiver.nxt_dcopy_cpu;
		request->skb = skb;
		request->offset = offset;
		request->len = used;
		request->remain_len = used;
		// dup_iter(&request->iter, &biter, GFP_KERNEL);
		request->iter = biter;
		// printk("queue_request:%d len:%d \n", dsk->receiver.nxt_dcopy_cpu, used);
		/* update the biter */
		iov_iter_advance(&biter, used);
		blen -= used;

		if(blen == 0) {
			request->bv_arr = bv_arr;
			request->max_segs = nr_segs;
			bv_arr = NULL;
			nr_segs = 0;
		}

		WRITE_ONCE(*seq, *seq + used);
		copied += used;
		len -= used;
		if (used + offset < skb->len)
			goto queue_request;
		// pr_info("copied_seq:%d\n", seq);
		WARN_ON(used + offset > skb->len);
		__skb_unlink(skb, &sk->sk_receive_queue);
		// atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
		// kfree_skb(skb);

queue_request:
		atomic_add(used, &dsk->receiver.in_flight_copy_bytes);
		/* queue the data copy request */
		
		qid = nd_dcopy_queue_request(request);
		// if(dsk->receiver.nxt_dcopy_cpu == -1) {
		// 	dsk->receiver.nxt_dcopy_cpu = qid;
		// 	// printk("new qid:%d\n", qid);
		// }
		// if(blen == 0 && bremain > 0) {
		// 	ssize_t bsize = bremain;
		// 	if(used + offset < skb->len) {
		// 		bsize =  min_t(ssize_t, bsize, skb->len - offset - used);
		// 	} else {
		// 		dsk->receiver.nxt_dcopy_cpu = -1;
		// 	}
		// 	bv_arr = kmalloc(MAX_PIN_PAGES * sizeof(struct bio_vec), GFP_KERNEL);
		// 	blen = nd_dcopy_iov_init(msg, &biter, bv_arr, bsize, max_segs);
		// 	nr_segs = biter.nr_segs;
		// 	bremain -= blen;
		// 	// sk_wait_data_copy(sk, &timeo);
		// }
		continue;
local_copy:
		if (!(flags & MSG_TRUNC)) {
			err = skb_copy_datagram_msg(skb, offset, msg, used);
			// printk("copy data done: %d\n", used);
			if (err) {
				WARN_ON(true);
				/* Exception. Bailout! */
				if (!copied)
					copied = -EFAULT;
				break;
			}
		}
		WRITE_ONCE(*seq, *seq + used);
		copied += used;
		len -= used;
		if (used + offset < skb->len)
			continue;
		__skb_unlink(skb, &sk->sk_receive_queue);
		// atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
		kfree_skb(skb);
		/* might need to call clean pages here */
	} while (len > 0);
	
	/* free the bvec memory */


	/* According to UNIX98, msg_name/msg_namelen are ignored
	 * on connected socket. I was just happy when found this 8) --ANK
	 */
	 	/* waiting data copy to be finishede */
	// while(atomic_read(&nsk->receiver.in_flight_copy_bytes) != 0) {

	sk_wait_data_copy(sk, &timeo);
	if(bv_arr) {
		nd_release_pages(bv_arr, true, nr_segs);
		kfree(bv_arr);
	}

	nd_try_send_ack(sk, copied);
	release_sock(sk);
	return copied;

out:
	release_sock(sk);
	return err;
}



/*
 * 	This should be easy, if there is something there we
 * 	return it, otherwise we block.
 */

int nd_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
		int flags, int *addr_len)
{

	struct nd_sock *dsk = nd_sk(sk);
	int copied = 0;
	// u32 peek_seq;
	u32 *seq;
	unsigned long used;
	int err;
	// int inq;
	int target;		/* Read at least this many bytes */
	long timeo;
	// int trigger_tokens = 1;
	struct sk_buff *skb, *last, *tmp;
	// u32 urg_hole = 0;
	// struct scm_timestamping_internal tss;
	// int cmsg_flags;
	// printk("recvmsg: sk->rxhash:%u\n", sk->sk_rxhash);
	// printk("rcvmsg core:%d\n", raw_smp_processor_id());

	// nd_rps_record_flow(sk);

	// if (unlikely(flags & MSG_ERRQUEUE))
	// 	return inet_recv_error(sk, msg, len, addr_len);
	// printk("start recvmsg \n");
	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);

	// printk("target bytes:%d\n", target);

	if (sk_can_busy_loop(sk) && skb_queue_empty_lockless(&sk->sk_receive_queue) &&
	    (sk->sk_state == ND_ESTABLISH))
		sk_busy_loop(sk, nonblock);

	lock_sock(sk);
	err = -ENOTCONN;


	// cmsg_flags = tp->recvmsg_inq ? 1 : 0;
	timeo = sock_rcvtimeo(sk, nonblock);

	if (sk->sk_state != ND_ESTABLISH)
		goto out;
	/* Urgent data needs to be handled specially. */
	// if (flags & MSG_OOB)
	// 	goto recv_urg;

	// if (unlikely(tp->repair)) {
	// 	err = -EPERM;
		// if (!(flags & MSG_PEEK))
		// 	goto out;

		// if (tp->repair_queue == TCP_SEND_QUEUE)
		// 	goto recv_sndq;

		// err = -EINVAL;
		// if (tp->repair_queue == TCP_NO_QUEUE)
		// 	goto out;

		/* 'common' recv queue MSG_PEEK-ing */
//	}

	seq = &dsk->receiver.copied_seq;
	// if (flags & MSG_PEEK) {
	// 	peek_seq = dsk->receiver.copied_seq;
	// 	seq = &peek_seq;
	// }

	do {
		u32 offset;

		/* Are we at urgent data? Stop if we have read anything or have SIGURG pending. */
		// if (tp->urg_data && tp->urg_seq == *seq) {
		// 	if (copied)
		// 		break;
		// 	if (signal_pending(current)) {
		// 		copied = timeo ? sock_intr_errno(timeo) : -EAGAIN;
		// 		break;
		// 	}
		// }

		/* Next get a buffer. */

		last = skb_peek_tail(&sk->sk_receive_queue);
		skb_queue_walk_safe(&sk->sk_receive_queue, skb, tmp) {
			last = skb;

			/* Now that we have two receive queues this
			 * shouldn't happen.
			 */
			if (WARN(before(*seq, ND_SKB_CB(skb)->seq),
				 "ND recvmsg seq # bug: copied %X, seq %X, rcvnxt %X, fl %X\n",
				 *seq, ND_SKB_CB(skb)->seq, dsk->receiver.rcv_nxt,
				 flags))
				break;

			offset = *seq - ND_SKB_CB(skb)->seq;
			// if (unlikely(TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN)) {
			// 	pr_err_once("%s: found a SYN, please report !\n", __func__);
			// 	offset--;
			// }
			if (offset < skb->len) {
				goto found_ok_skb; 
			}
			else {
				WARN_ON(true);
				// __skb_unlink(skb, &sk->sk_receive_queue);

				// kfree_skb(skb);
				// atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
			}
			// if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
			// 	goto found_fin_ok;
			// WARN(!(flags & MSG_PEEK),
			//      "TCP recvmsg seq # bug 2: copied %X, seq %X, rcvnxt %X, fl %X\n",
			//      *seq, ND_SKB_CB(skb)->seq, dsk->receiver.rcv_nxt, flags);
		}


		/* ToDo: we have to check whether pending requests are done */
		/* Well, if we have backlog, try to process it now yet. */

		if (copied >= target && !READ_ONCE(sk->sk_backlog.tail))
			break;

		if (copied) {
			if (sk->sk_err ||
			    sk->sk_state == TCP_CLOSE ||
			    (sk->sk_shutdown & RCV_SHUTDOWN) ||
			    !timeo ||
			    signal_pending(current))
				break;
		} else {
			if (sock_flag(sk, SOCK_DONE))
				break;

			if (sk->sk_err) {
				copied = sock_error(sk);
				break;
			}

			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;

			if (sk->sk_state == TCP_CLOSE) {
				/* This occurs when user tries to read
				 * from never connected socket.
				 */
				copied = -ENOTCONN;
				break;
			}

			if (!timeo) {
				copied = -EAGAIN;
				break;
			}

			if (signal_pending(current)) {
				copied = sock_intr_errno(timeo);
				break;
			}
		}

		// tcp_cleanup_rbuf(sk, copied);
		nd_try_send_ack(sk, copied);
		// printk("release sock");
		if (copied >= target) {
			/* Do not sleep, just process backlog. */
			/* Release sock will handle the backlog */
			// printk("call release sock1\n");
			release_sock(sk);
			lock_sock(sk);
		} else {
			sk_wait_data(sk, &timeo, last);
		}

		// if ((flags & MSG_PEEK) &&
		//     (peek_seq - copied - urg_hole != tp->copied_seq)) {
		// 	net_dbg_ratelimited("TCP(%s:%d): Application bug, race in MSG_PEEK\n",
		// 			    current->comm,
		// 			    task_pid_nr(current));
		// 	peek_seq = dsk->receiver.copied_seq;
		// }
		continue;

found_ok_skb:
		/* Ok so how much can we use? */
		used = skb->len - offset;
		if (len < used)
			used = len;
		// nd_try_send_token(sk);

		/* Do we have urgent data here? */
		// if (tp->urg_data) {
		// 	u32 urg_offset = tp->urg_seq - *seq;
		// 	if (urg_offset < used) {
		// 		if (!urg_offset) {
		// 			if (!sock_flag(sk, SOCK_URGINLINE)) {
		// 				WRITE_ONCE(*seq, *seq + 1);
		// 				urg_hole++;
		// 				offset++;
		// 				used--;
		// 				if (!used)
		// 					goto skip_copy;
		// 			}
		// 		} else
		// 			used = urg_offset;
		// 	}
		// }

		if (!(flags & MSG_TRUNC)) {
			err = skb_copy_datagram_msg(skb, offset, msg, used);
			// printk("copy data done: %d\n", used);
			if (err) {
				WARN_ON(true);
				/* Exception. Bailout! */
				if (!copied)
					copied = -EFAULT;
				break;
			}
		}

		WRITE_ONCE(*seq, *seq + used);
		copied += used;
		len -= used;
		if (used + offset < skb->len)
			continue;
		__skb_unlink(skb, &sk->sk_receive_queue);
		// atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
		kfree_skb(skb);

		// if (copied > 3 * trigger_tokens * dsk->receiver.max_gso_data) {
		// 	// nd_try_send_token(sk);
		// 	trigger_tokens += 1;
			
		// }
		// nd_try_send_token(sk);

		// tcp_rcv_space_adjust(sk);

// skip_copy:
		// if (tp->urg_data && after(tp->copied_seq, tp->urg_seq)) {
		// 	tp->urg_data = 0;
		// 	tcp_fast_path_check(sk);
		// }
		// if (used + offset < skb->len)
		// 	continue;

		// if (TCP_SKB_CB(skb)->has_rxtstamp) {
		// 	tcp_update_recv_tstamps(skb, &tss);
		// 	cmsg_flags |= 2;
		// }
		// if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
		// 	goto found_fin_ok;
		// if (!(flags & MSG_PEEK))
		// 	sk_eat_skb(sk, skb);
		continue;

// found_fin_ok:
		/* Process the FIN. */
		// WRITE_ONCE(*seq, *seq + 1);
		// if (!(flags & MSG_PEEK))
		// 	sk_eat_skb(sk, skb);
		// break;
	} while (len > 0);

	/* According to UNIX98, msg_name/msg_namelen are ignored
	 * on connected socket. I was just happy when found this 8) --ANK
	 */
	
	/* Clean up data we have read: This will do ACK frames. */
	// tcp_cleanup_rbuf(sk, copied);
	nd_try_send_ack(sk, copied);
	// if (dsk->receiver.copied_seq == dsk->total_length) {
	// 	printk("call tcp close in the recv msg\n");
	// 	nd_set_state(sk, TCP_CLOSE);
	// } else {
	// 	// nd_try_send_token(sk);
	// }
	release_sock(sk);

	// if (cmsg_flags) {
	// 	if (cmsg_flags & 2)
	// 		tcp_recv_timestamp(msg, sk, &tss);
	// 	if (cmsg_flags & 1) {
	// 		inq = tcp_inq_hint(sk);
	// 		put_cmsg(msg, SOL_TCP, TCP_CM_INQ, sizeof(inq), &inq);
	// 	}
	// }
	// printk("recvmsg\n");
	return copied;

out:
	release_sock(sk);
	return err;

// recv_urg:
// 	err = tcp_recv_urg(sk, msg, len, flags);
// 	goto out;

// recv_sndq:
// 	// err = tcp_peek_sndq(sk, msg, len);
// 	goto out;
}

int nd_pre_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	if (addr_len < sizeof(struct sockaddr_in))
 		return -EINVAL;

 	return BPF_CGROUP_RUN_PROG_INET4_CONNECT_LOCK(sk, uaddr);
}
EXPORT_SYMBOL(nd_pre_connect);

int nd_disconnect(struct sock *sk, int flags)
{
	struct inet_sock *inet = inet_sk(sk);
 	/*
 	 *	1003.1g - break association.
 	 */

 	sk->sk_state = TCP_CLOSE;
 	inet->inet_daddr = 0;
 	inet->inet_dport = 0;
 	// sock_rps_reset_rxhash(sk);
 	sk->sk_bound_dev_if = 0;
 	if (!(sk->sk_userlocks & SOCK_BINDADDR_LOCK)) {
 		inet_reset_saddr(sk);
 		if (sk->sk_prot->rehash &&
 		    (sk->sk_userlocks & SOCK_BINDPORT_LOCK))
 			sk->sk_prot->rehash(sk);
 	}

 	if (!(sk->sk_userlocks & SOCK_BINDPORT_LOCK)) {
 		sk->sk_prot->unhash(sk);
 		inet->inet_sport = 0;
 	}
 	sk_dst_reset(sk);
 	return 0;
}
EXPORT_SYMBOL(nd_disconnect);

int nd_v4_early_demux(struct sk_buff *skb)
{
	// struct net *net = dev_net(skb->dev);
	// struct in_device *in_dev = NULL;
	// const struct iphdr *iph;
	// const struct ndhdr *uh;
	// struct sock *sk = NULL;
	// struct dst_entry *dst;
	// int dif = skb->dev->ifindex;
	// int sdif = inet_sdif(skb);
	// int ours;

	/* validate the packet */
	// printk("early demux");
	return 0; 
	// if(skb->pkt_type != PACKET_HOST) {
	// 	return 0;
	// }
	// if (!pskb_may_pull(skb, skb_transport_offset(skb) + sizeof(struct ndhdr)))
	// 	return 0;

	// iph = ip_hdr(skb);
	// uh = nd_hdr(skb);

    // // if (th->doff < sizeof(struct tcphdr) / 4)
    // //             return 0;
    // sk = __nd_lookup_established(dev_net(skb->dev), &nd_hashinfo,
    //                                iph->saddr, uh->source,
    //                                iph->daddr, ntohs(uh->dest),
    //                                skb->skb_iif, sdif);

    // if (sk) {
    //         skb->sk = sk;
    //         skb->destructor = sock_edemux;
    //         if (sk_fullsock(sk)) {
    //                 struct dst_entry *dst = READ_ONCE(sk->sk_rx_dst);

    //                 if (dst)
    //                         dst = dst_check(dst, 0);
    //                 if (dst &&
    //                     inet_sk(sk)->rx_dst_ifindex == skb->skb_iif)
    //                         skb_dst_set_noref(skb, dst);
    //         }
    // }
	// return 0;
}


int nd_rcv(struct sk_buff *skb)
{
	// printk("receive nd rcv\n");
	// skb_dump(KERN_WARNING, skb, false);
	struct ndhdr* dh;
	// printk("skb->len:%d\n", skb->len);
	WARN_ON(skb == NULL);

	if (!pskb_may_pull(skb, sizeof(struct ndhdr)))
		goto drop;		/* No space for header. */

	dh = nd_hdr(skb);
	// printk("dh == NULL?: %d\n", dh == NULL);
	// printk("receive pkt: %d\n", dh->type);
	// printk("end ref \n");
	if(dh->type == DATA) {
		return nd_handle_data_pkt(skb);
		// return __nd4_lib_rcv(skb, &nd_table, IPPROTO_VIRTUAL_SOCK);
	} else if (dh->type == SYNC) {
		return nd_handle_sync_pkt(skb);
	} else if (dh->type == TOKEN) {
		WARN_ON(true);
		return nd_handle_token_pkt(skb);
	} else if (dh->type == FIN) {
		return nd_handle_fin_pkt(skb);
	} else if (dh->type == ACK) {
		return nd_handle_ack_pkt(skb);
	} else if (dh->type == SYNC_ACK) {
		return nd_handle_sync_ack_pkt(skb);
	}
	//  else if (dh->type == SYNC_ACK) {
	// 	return nd_handle_sync_ack_pkt(skb);
	// }
	// else if (dh->type == RTS) {
	// 	return nd_handle_rts(skb, &nd_match_table, &nd_epoch);
	// } else if (dh->type == GRANT) {
	// 	return nd_handle_grant(skb, &nd_match_table, &nd_epoch);
	// } else if (dh->type == ACCEPT) {
	// 	return nd_handle_accept(skb, &nd_match_table, &nd_epoch);
	// }


drop:

	kfree_skb(skb);
	return 0;

	return 0;
	// return __nd4_lib_rcv(skb, &nd_table, IPPROTO_VIRTUAL_SOCK);
}


void nd_destroy_sock(struct sock *sk)
{
	// struct udp_hslot* hslot = udp_hashslot(sk->sk_prot->h.udp_table, sock_net(sk),
	// 				     nd_sk(sk)->nd_port_hash);
	struct nd_sock *up = nd_sk(sk);
	// struct inet_sock *inet = inet_sk(sk);
	// struct rcv_core_entry *entry = &rcv_core_tab.table[raw_smp_processor_id()];
	// local_bh_disable();
	// bh_lock_sock(sk);
	// hrtimer_cancel(&up->receiver.flow_wait_timer);
	// test_and_clear_bit(ND_WAIT_DEFERRED, &sk->sk_tsq_flags);
	lock_sock(sk);
	up->receiver.flow_finish_wait = false;
	if(sk->sk_state == ND_ESTABLISH) {
		// printk("send fin pkt\n");
		nd_conn_queue_request(construct_fin_req(sk), false, true);
		// nd_xmit_control(construct_fin_pkt(sk), sk, inet->inet_dport); 
	}      
	// printk("reach here:%d", __LINE__);
	// pr_info("up->sender.snd_una:%u\n", up->sender.snd_una);
	// pr_info("up->sender.grant_nxt:%u\n", up->sender.sd_grant_nxt);
	// pr_info("up->sender.write_seq:%u\n", up->sender.write_seq);
	// pr_info("up->receiver.grant_nxt:%u\n", up->receiver.grant_nxt);
	// pr_info("up->receiver.free_skb_num:%llu\n", up->receiver.free_skb_num);
	// pr_info("sk->sk_wmem_queued:%u\n", sk->sk_wmem_queued);
	nd_set_state(sk, TCP_CLOSE);
	// nd_flush_pendfing_frames(sk);
	if(up->sender.pending_req) {
		// pr_info("up->sender.pending_req seq:%u\n", ND_SKB_CB(up->sender.pending_req->skb)->seq);
		kfree_skb(up->sender.pending_req->skb);
		kfree(up->sender.pending_req);
		up->sender.pending_req = NULL;
	}
	nd_write_queue_purge(sk);
	nd_read_queue_purge(sk);
	// pr_info("sk->sk_wmem_queued:%u\n", sk->sk_wmem_queued);

	release_sock(sk);
	/* remove from sleep wait queue */
	nd_conn_remove_sleep_sock(nd_ctrl, up);
	cancel_work_sync(&up->tx_work);
	/*  */
	// bh_unlock_sock(sk);
	// local_bh_enable();

	// printk("sk->sk_wmem_queued:%d\n",sk->sk_wmem_queued);
	// spin_lock_bh(&entry->lock);
	// printk("dsk->match_link:%p\n", &up->match_link);
	// if(up->receiver.in_pq)
		// nd_pq_delete(&entry->flow_q, &up->match_link);
	// spin_unlock_bh(&entry->lock);
	// if (static_branch_unlikely(&nd_encap_needed_key)) {
	// 	if (up->encap_type) {
	// 		void (*encap_destroy)(struct sock *sk);
	// 		encap_destroy = READ_ONCE(up->encap_destroy);
	// 		if (encap_destroy)
	// 			encap_destroy(sk);
	// 	}
	// 	if (up->encap_enabled)
	// 		static_branch_dec(&nd_encap_needed_key);
	// }
}


int nd_setsockopt(struct sock *sk, int level, int optname,
		   char __user *optval, unsigned int optlen)
{
	printk(KERN_WARNING "unimplemented setsockopt invoked on ND socket:"
			" level %d, optname %d, optlen %d\n",
			level, optname, optlen);
	return -EINVAL;
	// if (level == SOL_VIRTUAL_SOCK)
	// 	return nd_lib_setsockopt(sk, level, optname, optval, optlen,
	// 				  nd_push_pending_frames);
	// return ip_setsockopt(sk, level, optname, optval, optlen);
}

// #ifdef CONFIG_COMPAT
// int compat_nd_setsockopt(struct sock *sk, int level, int optname,
// 			  char __user *optval, unsigned int optlen)
// {
// 	if (level == SOL_VIRTUAL_SOCK)
// 		return nd_lib_setsockopt(sk, level, optname, optval, optlen,
// 					  nd_push_pending_frames);
// 	return compat_ip_setsockopt(sk, level, optname, optval, optlen);
// }
// #endif

int nd_lib_getsockopt(struct sock *sk, int level, int optname,
		       char __user *optval, int __user *optlen)
{
	printk(KERN_WARNING "unimplemented getsockopt invoked on ND socket:"
			" level %d, optname %d\n", level, optname);
	return -EINVAL;
	// struct nd_sock *up = nd_sk(sk);
	// int val, len;

	// if (get_user(len, optlen))
	// 	return -EFAULT;

	// len = min_t(unsigned int, len, sizeof(int));

	// if (len < 0)
	// 	return -EINVAL;

	// switch (optname) {
	// case ND_CORK:
	// 	val = up->corkflag;
	// 	break;

	// case ND_ENCAP:
	// 	val = up->encap_type;
	// 	break;

	// case ND_NO_CHECK6_TX:
	// 	val = up->no_check6_tx;
	// 	break;

	// case ND_NO_CHECK6_RX:
	// 	val = up->no_check6_rx;
	// 	break;

	// case ND_SEGMENT:
	// 	val = up->gso_size;
	// 	break;
	// default:
	// 	return -ENOPROTOOPT;
	// }

	// if (put_user(len, optlen))
	// 	return -EFAULT;
	// if (copy_to_user(optval, &val, len))
	// 	return -EFAULT;
	// return 0;
}
EXPORT_SYMBOL(nd_lib_getsockopt);

int nd_getsockopt(struct sock *sk, int level, int optname,
		   char __user *optval, int __user *optlen)
{
	printk(KERN_WARNING "unimplemented getsockopt invoked on ND socket:"
			" level %d, optname %d\n", level, optname);
	return -EINVAL;
}

__poll_t nd_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	printk(KERN_WARNING "unimplemented poll invoked on ND socket\n");
	return -ENOSYS;
}
EXPORT_SYMBOL(nd_poll);

int nd_abort(struct sock *sk, int err)
{
	printk(KERN_WARNING "unimplemented abort invoked on ND socket\n");
	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(nd_abort);

u32 nd_flow_hashrnd(void)
{
	static u32 hashrnd __read_mostly;

	net_get_random_once(&hashrnd, sizeof(hashrnd));

	return hashrnd;
}
EXPORT_SYMBOL(nd_flow_hashrnd);

// static void __nd_sysctl_init(struct net *net)
// {
// 	net->ipv4.sysctl_udp_rmem_min = SK_MEM_QUANTUM;
// 	net->ipv4.sysctl_udp_wmem_min = SK_MEM_QUANTUM;

// #ifdef CONFIG_NET_L3_MASTER_DEV
// 	net->ipv4.sysctl_udp_l3mdev_accept = 0;
// #endif
// }

// static int __net_init nd_sysctl_init(struct net *net)
// {
// 	__nd_sysctl_init(net);
// 	return 0;
// }

// static struct pernet_operations __net_initdata nd_sysctl_ops = {
// 	.init	= nd_sysctl_init,
// };

void __init nd_init(void)
{
	unsigned long limit;
	// unsigned int i;

	printk("try to add nd table \n");

	nd_hashtable_init(&nd_hashinfo, 0);

	limit = nr_free_buffer_pages() / 8;
	limit = max(limit, 128UL);
	sysctl_nd_mem[0] = limit / 4 * 3;
	sysctl_nd_mem[1] = limit;
	sysctl_nd_mem[2] = sysctl_nd_mem[0] * 2;

	// __nd_sysctl_init(&init_net);
	// /* 16 spinlocks per cpu */
	// // nd_busylocks_log = ilog2(nr_cpu_ids) + 4;
	// // nd_busylocks = kmalloc(sizeof(spinlock_t) << nd_busylocks_log,
	// // 			GFP_KERNEL);
	// // if (!nd_busylocks)
	// // 	panic("ND: failed to alloc nd_busylocks\n");
	// // for (i = 0; i < (1U << nd_busylocks_log); i++)
	// // 	spin_lock_init(nd_busylocks + i);
	// if (register_pernet_subsys(&nd_sysctl_ops)) 
	// 	panic("ND: failed to init sysctl parameters.\n");

	printk("ND init complete\n");

}

void nd_destroy() {
	printk("try to destroy peer table\n");
	printk("try to destroy nd socket table\n");
	nd_hashtable_destroy(&nd_hashinfo);
	// kfree(nd_busylocks);
}
