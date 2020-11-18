#ifndef _ND_HOST_H
#define _ND_HOST_H

#include <linux/module.h>
#include <linux/inet.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/err.h>
// #include <linux/nvme-tcp.h>
#include <net/sock.h>
#include <net/tcp.h>
// #include <linux/blk-mq.h>
#include <crypto/hash.h>
#include <net/busy_poll.h>
#include "uapi_linux_nd.h"
#include "linux_nd.h"
extern struct nd_conn_ctrl* nd_ctrl;

#define ND_CONN_AQ_DEPTH		32
enum hctx_type {
	HCTX_TYPE_DEFAULT,
	HCTX_TYPE_READ,
	HCTX_TYPE_POLL,

	HCTX_MAX_TYPES,
};

enum nd_conn_send_state {
	ND_CONN_SEND_CMD_PDU = 0,
	ND_CONN_SEND_H2C_PDU,
	ND_CONN_SEND_DATA,
	ND_CONN_SEND_DDGST,
	ND_CONN_PDU_DONE,
};

enum nd_conn_queue_flags {
	ND_CONN_Q_ALLOCATED	= 0,
	ND_CONN_Q_LIVE		= 1,
	ND_CONN_Q_POLLING	= 2,
};

struct nd_conn_ctrl_options {
	// unsigned		mask;
	// char			*transport;
	// char			*subsysnqn;
	char			*traddr;
	char			*trsvcid;
	char			*host_traddr;
    // char            *host_port;
	size_t			queue_size;
	unsigned int		nr_io_queues;
	// unsigned int		reconnect_delay;
	// bool			discovery_nqn;
	// bool			duplicate_connect;
	// unsigned int		kato;
	struct nvmf_host	*host;
	// int			max_reconnects;
	// bool			disable_sqflow;
	// bool			hdr_digest;
	// bool			data_digest;
	unsigned int		nr_write_queues;
	unsigned int		nr_poll_queues;
	int			tos;
};


struct nd_conn_request {
	// struct nvme_request	req;
	struct ndhdr	*hdr;
	struct sk_buff	*skb;
	struct nd_conn_queue	*queue;
	// u32			data_len;
	// u32			pdu_len;
	// u32			pdu_sent;
	
	u16			ttag;

	struct list_head	entry;
	struct llist_node	lentry;
	// __le32			ddgst;

	// struct bio		*curr_bio;
	struct iov_iter		iter;

	/* send state */
	size_t			offset;
	size_t			data_sent;
	size_t			frag_offset;
	size_t			fragidx;
	enum nd_conn_send_state state;
};

struct nd_conn_ctrl {
	/* read only in the hot path */
	struct nd_conn_queue	*queues;
    uint32_t queue_count;
	// struct blk_mq_tag_set	tag_set;

	/* other member variables */
	struct list_head	list;
	/* socket wait list */
	struct mutex sock_wait_lock;
	struct list_head sock_wait_list;
	struct workqueue_struct *sock_wait_wq;

	// struct blk_mq_tag_set	admin_tag_set;
	struct sockaddr_storage addr;
	struct sockaddr_storage src_addr;
	// struct nvme_ctrl	ctrl;
    struct nd_conn_ctrl_options *opts;
    uint32_t sqsize;
	struct mutex		teardown_lock;
	// struct work_struct	err_work;
	// struct delayed_work	connect_work;
	// struct nd_conn_request async_req;
	u32			io_queues[32];
	struct page_frag_cache	pf_cache;

};

struct nd_conn_queue {
	struct socket		*sock;
	struct work_struct	io_work;
	int			io_cpu;

	struct mutex		send_mutex;
	struct llist_head	req_list;
	struct list_head	send_list;
	bool			more_requests;

	/* recv state */
	// void			*pdu;
	// int			pdu_remaining;
	// int			pdu_offset;
	// size_t			data_remaining;
	// size_t			ddgst_remaining;
	// unsigned int		nr_cqe;

	/* send state */
	struct nd_conn_request *request;
	atomic_t	cur_queue_size;
	int			queue_size;
	// int			cur_queue_size;
	// size_t			cmnd_capsule_len;
	struct nd_conn_ctrl	*ctrl;
	unsigned long		flags;
	bool			rd_enabled;

	// bool			hdr_digest;
	// bool			data_digest;
	// struct ahash_request	*rcv_hash;
	// struct ahash_request	*snd_hash;
	// __le32			exp_ddgst;
	// __le32			recv_ddgst;

	// struct page_frag_cache	pf_cache;

	void (*state_change)(struct sock *);
	void (*data_ready)(struct sock *);
	void (*write_space)(struct sock *);
};


struct nd_conn_pdu {
	struct ndhdr hdr;
};

void nd_conn_add_sleep_sock(struct nd_conn_ctrl *ctrl, struct nd_sock* nsk);
void nd_conn_remove_sleep_sock(struct nd_conn_ctrl *ctrl, struct nd_sock *nsk);
void nd_conn_wake_up_all_socks(struct nd_conn_ctrl *ctrl);

int nd_conn_init_request(struct nd_conn_request *req, int queue_id);
int nd_conn_try_send_cmd_pdu(struct nd_conn_request *req); 
int nd_conn_try_send_data_pdu(struct nd_conn_request *req);
int nd_conn_try_send(struct nd_conn_queue *queue);
void nd_conn_restore_sock_calls(struct nd_conn_queue *queue);
void __nd_conn_stop_queue(struct nd_conn_queue *queue);
void nd_conn_stop_queue(struct nd_conn_ctrl *ctrl, int qid);
void nd_conn_free_queue(struct nd_conn_ctrl *ctrl, int qid);
void nd_conn_free_io_queues(struct nd_conn_ctrl *ctrl);
void nd_conn_stop_io_queues(struct nd_conn_ctrl *ctrl);
int nd_conn_start_queue(struct nd_conn_ctrl *ctrl, int idx);
int nd_conn_configure_admin_queue(struct nd_conn_ctrl *ctrl, bool new);
int nd_conn_alloc_admin_queue(struct nd_conn_ctrl *ctrl);
void nd_conn_free_admin_queue(struct nd_conn_ctrl *ctrl);
void nd_conn_destroy_admin_queue(struct nd_conn_ctrl *ctrl, bool remove);
void nd_conn_io_work(struct work_struct *w);
void nd_conn_data_ready(struct sock *sk);
void nd_conn_write_space(struct sock *sk);
void nd_conn_state_change(struct sock *sk);
void nd_conn_data_ready(struct sock *sk);
int nd_conn_alloc_queue(struct nd_conn_ctrl *ctrl,
		int qid, size_t queue_size);
bool nd_conn_queue_request(struct nd_conn_request *req,
		bool sync, bool avoid_check);
// void nd_conn_error_recovery_work(struct work_struct *work);
void nd_conn_teardown_ctrl(struct nd_conn_ctrl *ctrl, bool shutdown);
void nd_conn_delete_ctrl(struct nd_conn_ctrl *ctrl);
void nd_conn_teardown_admin_queue(struct nd_conn_ctrl *ctrl,
		bool remove);
void nd_conn_teardown_io_queues(struct nd_conn_ctrl *ctrl,
		bool remove);
unsigned int nd_conn_nr_io_queues(struct nd_conn_ctrl *ctrl);
int __nd_conn_alloc_io_queues(struct nd_conn_ctrl *ctrl);
void nd_conn_destroy_io_queues(struct nd_conn_ctrl *ctrl, bool remove);
int nd_conn_setup_ctrl(struct nd_conn_ctrl *ctrl, bool new);
struct nd_conn_ctrl *nd_conn_create_ctrl(struct nd_conn_ctrl_options *opts);
int nd_conn_init_module(void);
void nd_conn_cleanup_module(void);
#endif
