/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ND_IMPL_H
#define _ND_IMPL_H
#include <net/udp.h>
#include <net/udplite.h>
#include <net/protocol.h>
#include <net/inet_common.h>

#include "net_nd.h"
#include "nd_hashtables.h"
#include "nd_sock.h"
#include "nd_target.h"
extern struct inet_hashinfo nd_hashinfo;
extern struct nd_params nd_params;
extern struct request_sock_ops nd_request_sock_ops;

// extern struct xmit_core_table xmit_core_tab;
// extern struct rcv_core_table rcv_core_tab;
void* allocate_hash_table(const char *tablename,
				     unsigned long bucketsize,
				     unsigned long numentries,
				     int scale,
				     int flags,
				     unsigned int *_hash_shift,
				     unsigned int *_hash_mask,
				     unsigned long low_limit,
				     unsigned long high_limit);
int nd_dointvec(struct ctl_table *table, int write,
                void __user *buffer, size_t *lenp, loff_t *ppos);
void nd_sysctl_changed(struct nd_params *params);
void nd_params_init(struct nd_params *params);

/*ND incoming function*/
int pass_to_vs_layer(struct ndt_conn_queue *ndt_queue, struct sk_buff_head* queue);
// bool nd_try_send_token(struct sock *sk);
// void nd_get_sack_info(struct sock *sk, struct sk_buff *skb);
// enum hrtimer_restart nd_new_epoch(struct hrtimer *timer);
int nd_handle_data_pkt(struct sk_buff *skb);
// int nd_handle_flow_sync_pkt(struct sk_buff *skb);
int nd_handle_sync_pkt(struct sk_buff *skb);
// int nd_handle_sync_pkt(struct sk_buff *skb);
int nd_handle_token_pkt(struct sk_buff *skb);
int nd_handle_fin_pkt(struct sk_buff *skb);
int nd_handle_ack_pkt(struct sk_buff *skb);
int nd_handle_sync_ack_pkt(struct sk_buff *skb);

int nd_data_queue(struct sock *sk, struct sk_buff *skb);
bool nd_add_backlog(struct sock *sk, struct sk_buff *skb, bool omit_check);
int nd_v4_do_rcv(struct sock *sk, struct sk_buff *skb);

// void nd_token_timer_defer_handler(struct sock *sk);
int nd_clean_rtx_queue(struct sock *sk);

void nd_page_pool_recycle_pages(struct sk_buff *skb);
// void nd_flow_wait_handler(struct sock *sk);

/*ND outgoing function*/
int nd_init_request(struct sock* sk, struct nd_conn_request *req);
struct nd_conn_request* construct_sync_req(struct sock* sk);
struct nd_conn_request* construct_sync_ack_req(struct sock* sk);
struct nd_conn_request* construct_fin_req(struct sock* sk);
struct nd_conn_request* construct_ack_req(struct sock* sk, gfp_t flag);

// struct sk_buff* construct_flow_sync_pkt(struct sock* sk, __u64 message_id, 
// 	uint32_t message_size, __u64 start_time);
// struct sk_buff* construct_token_pkt(struct sock* sk, unsigned short priority, __u32 prev_grant_nxt,
// 	 __u32 grant_nxt, bool handle_rtx);
void nd_write_queue_purge(struct sock *sk);

void nd_release_cb(struct sock *sk);
int __nd4_lib_rcv(struct sk_buff *, struct udp_table *, int);
int __nd4_lib_err(struct sk_buff *, u32, struct udp_table *);

int nd_v4_get_port(struct sock *sk, unsigned short snum);
void nd_v4_rehash(struct sock *sk);

int nd_setsockopt(struct sock *sk, int level, int optname,
		   char __user *optval, unsigned int optlen);
int nd_getsockopt(struct sock *sk, int level, int optname,
		   char __user *optval, int __user *optlen);

#ifdef CONFIG_COMPAT
int compat_nd_setsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, unsigned int optlen);
int compat_nd_getsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int __user *optlen);
#endif
int nd_push(struct sock *sk, gfp_t flag);

void nd_release_pages(struct bio_vec* bv_arr, bool mark_dirty, int max_segs);
int nd_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int noblock,
		int flags, int *addr_len);
/* new recvmsg syscall */
int nd_recvmsg_new(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
		int flags, int *addr_len);
int nd_recvmsg_new_2(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
		int flags, int *addr_len);
int nd_sendpage(struct sock *sk, struct page *page, int offset, size_t size,
		 int flags);
void nd_destroy_sock(struct sock *sk);

#ifdef CONFIG_PROC_FS
int udp4_seq_show(struct seq_file *seq, void *v);
#endif
#endif	/* _UDP4_IMPL_H */

