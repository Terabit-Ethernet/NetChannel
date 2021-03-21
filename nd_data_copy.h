#ifndef _ND_DATA_COPY_H
#define _ND_DATA_COPY_H

#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/err.h>
// #include <linux/nvme-tcp.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/inet.h>
#include <linux/llist.h>
#include <linux/spinlock.h>
#include <crypto/hash.h>
#include "uapi_linux_nd.h"

enum nd_conn_dcopy_state {
	ND_DCOPY_SEND = 0,
	ND_DCOPY_RECV,
	ND_DCOPY_DONE,
};


struct nd_dcopy_response {
	struct llist_node	lentry;
	struct sk_buff *skb;
};

struct nd_dcopy_page {
	struct llist_node	lentry;
	struct bio_vec *bv_arr;
	struct sk_buff* skb;
	int max_segs;
};

struct nd_dcopy_request {
	enum nd_conn_dcopy_state state;

	bool clean_skb;
	int io_cpu;
    struct sock *sk;
	struct sk_buff *skb;
	struct iov_iter iter;
	struct bio_vec *bv_arr;
	struct list_head	entry;
	struct llist_node	lentry;
	union{
		u32 offset;
		u32 seq;
	};
    int len;
	int remain_len;
	int max_segs;
	struct nd_dcopy_queue *queue;
};

struct nd_dcopy_queue {
    struct llist_head	req_list;
	struct list_head	copy_list;
    int io_cpu;
	struct work_struct	io_work;
	struct mutex		copy_mutex;

    struct nd_dcopy_request *request;
    size_t			offset;
	int queue_threshold;
	atomic_t	queue_size;
};

// inline void nd_init_data_copy_request(struct nd_dcopy_request *request) {
//     request->clean_skb = false;
//     // INIT_LIST_HEAD();
//     // init_llist_head
// }
int nd_dcopy_sche_rr(int last_qid);
int nd_dcopy_queue_request(struct nd_dcopy_request *req);
int nd_try_dcopy(struct nd_dcopy_queue *queue);
void nd_dcopy_io_work(struct work_struct *w);
void nd_dcopy_flush_req_list(struct nd_dcopy_queue *queue);
void nd_dcopy_free_queue(struct nd_dcopy_queue *queue);
int nd_dcopy_alloc_queue(struct nd_dcopy_queue *queue, int io_cpu);
int nd_dcopy_alloc_queues(struct nd_dcopy_queue *queues);
int nd_dcopy_init(void);
void nd_dcopy_exit(void);

#endif /* _ND_DATA_COPY_H */
