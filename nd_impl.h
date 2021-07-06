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
extern struct nd_peertab nd_peers_table;
extern struct nd_match_tab nd_match_table;

extern struct nd_params nd_params;
extern struct nd_epoch nd_epoch;
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
// ND matching logic
// ND priority queue
// int calc_grant_bytes(struct sock *sk);
// int xmit_batch_token(struct sock *sk, int grant_bytes, bool handle_rtx);
// void nd_xmit_token(struct nd_epoch* epoch);
// int rtx_bytes_count(struct nd_sock* dsk, __u32 prev_grant_nxt);
// void nd_xmit_token_handler(struct work_struct *work);
// enum hrtimer_restart nd_token_xmit_event(struct hrtimer *timer);
void nd_pq_init(struct nd_pq* pq, bool(*comp)(const struct list_head*, const struct list_head*));
bool nd_pq_empty(struct nd_pq* pq);
bool nd_pq_empty_lockless(struct nd_pq* pq);
struct list_head* nd_pq_pop(struct nd_pq* pq);
void nd_pq_push(struct nd_pq* pq, struct list_head* node);
struct list_head* nd_pq_peek(struct nd_pq* pq); 
void nd_pq_delete(struct nd_pq* pq, struct list_head* node);
int nd_pq_size(struct nd_pq* pq);

// void nd_match_entry_init(struct nd_match_entry* entry, __be32 addr, 
//  bool(*comp)(const struct list_head*, const struct list_head*));
// void nd_mattab_init(struct nd_match_tab *table,
// 	bool(*comp)(const struct list_head*, const struct list_head*));

// void nd_mattab_destroy(struct nd_match_tab *table);
// void nd_mattab_add_new_sock(struct nd_match_tab *table, struct sock *sk);
// void nd_mattab_delete_sock(struct nd_match_tab *table, struct sock *sk);

// void nd_mattab_delete_match_entry(struct nd_match_tab *table, struct nd_match_entry* entry);


// void nd_epoch_init(struct nd_epoch *epoch);
// void nd_epoch_destroy(struct nd_epoch *epoch);
// void nd_send_all_rts (struct nd_match_tab *table, struct nd_epoch* epoch);

// int nd_handle_rts (struct sk_buff *skb, struct nd_match_tab *table, struct nd_epoch *epoch);

// void nd_handle_all_rts(struct nd_match_tab* table, struct nd_epoch *epoch);
// int nd_handle_grant(struct sk_buff *skb, struct nd_match_tab *table, struct nd_epoch *epoch);
// void nd_handle_all_grants(struct nd_match_tab *table, struct nd_epoch *epoch);
// int nd_handle_accept(struct sk_buff *skb, struct nd_match_tab *table, struct nd_epoch *epoch);


/* scheduling */
// bool flow_compare(const struct list_head* node1, const struct list_head* node2);
// void rcv_core_entry_init(struct rcv_core_entry *entry, int core_id);
// int rcv_core_table_init(struct rcv_core_table *tab);
// void xmit_core_entry_init(struct xmit_core_entry *entry, int core_id);
// int xmit_core_table_init(struct xmit_core_table *tab);
// void rcv_core_table_destory(struct rcv_core_table *tab);
// void xmit_core_table_destory(struct xmit_core_table *tab);
// void nd_update_and_schedule_sock(struct nd_sock *dsk);
// void nd_unschedule_sock(struct nd_sock *dsk);
/* sender */
// void xmit_handle_new_token(struct xmit_core_table *tab, struct sk_buff* skb);
// void nd_xmit_data_event(struct work_struct *w);

/* receiver */
// void nd_xmit_token_event(struct work_struct *w);
// void rcv_handle_new_flow(struct nd_sock* dsk);
// void rcv_flowlet_done(struct rcv_core_entry *entry);
// enum hrtimer_restart flowlet_done_event(struct hrtimer *timer);



// int nd_fragment(struct sock *sk, enum nd_queue nd_queue,
// 		 struct sk_buff *skb, u32 len,
// 		 unsigned int mss_now, gfp_t gfp);
// int nd_fill_packets(struct sock *sk,
// 		struct msghdr *msg, size_t len);

/*ND peer table*/
// int nd_peertab_init(struct nd_peertab *peertab);
// void nd_peertab_destroy(struct nd_peertab *peertab);
// struct nd_peer *nd_peer_find(struct nd_peertab *peertab, __be32 addr,
// 	struct inet_sock *inet);

/*ND incoming function*/
int pass_to_vs_layer(struct ndt_conn_queue *ndt_queue, struct sk_buff_head* queue);
// bool nd_try_send_token(struct sock *sk);
// void nd_get_sack_info(struct sock *sk, struct sk_buff *skb);
// enum hrtimer_restart nd_new_epoch(struct hrtimer *timer);
int nd_handle_hol_data_pkt(struct sk_buff *skb);
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

// void nd_rem_check_handler(struct sock *sk);
// void nd_token_timer_defer_handler(struct sock *sk);
int nd_clean_rtx_queue(struct sock *sk);

void nd_page_pool_recycle_pages(struct sk_buff *skb);
// enum hrtimer_restart nd_flow_wait_event(struct hrtimer *timer);
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
struct sk_buff* construct_fin_pkt(struct sock* sk);
struct sk_buff* construct_ack_pkt(struct sock* sk, __be32 rcv_nxt);
struct sk_buff* construct_rts_pkt(struct sock* sk, unsigned short iter, int epoch, int remaining_sz);
struct sk_buff* construct_grant_pkt(struct sock* sk, unsigned short iter, int epoch, int remaining_sz, bool prompt);
struct sk_buff* construct_accept_pkt(struct sock* sk, unsigned short iter, int epoch);
int nd_xmit_control(struct sk_buff* skb, struct sock *nd_sk, int dport);
void nd_xmit_data(struct sk_buff *skb, struct nd_sock* dsk, bool free_token);
void nd_retransmit_data(struct sk_buff *skb, struct nd_sock* dsk);
void __nd_xmit_data(struct sk_buff *skb, struct nd_sock* dsk, bool free_token);
void nd_retransmit(struct sock* sk);

int nd_write_timer_handler(struct sock *sk);

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

