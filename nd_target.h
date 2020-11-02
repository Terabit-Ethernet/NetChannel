
#ifndef _ND_TARGET_H
#define _ND_TARGET_H

#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/err.h>
// #include <linux/nvme-tcp.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/inet.h>
#include <linux/llist.h>
#include <crypto/hash.h>
#include "uapi_linux_nd.h"
// #include "nd_host.h"
/* ND Connection Listerning Port */
struct ndt_conn_port {
	struct socket		*sock;
	struct work_struct	accept_work;
	// struct nvmet_port	*nport;
	struct sockaddr_storage addr;
	char* local_ip;
	char* local_port;
	void (*data_ready)(struct sock *);
	
};

enum ndt_conn_queue_state {
	NDT_CONN_Q_CONNECTING,
	NDT_CONN_Q_LIVE,
	NDT_CONN_Q_DISCONNECTING,
};

enum ndt_conn_recv_state {
	NDT_CONN_RECV_PDU,
	NDT_CONN_RECV_DATA,
	NDT_CONN_RECV_DDGST,
	NDT_CONN_RECV_ERR,
};

struct ndt_conn_queue {
	struct socket		*sock;
	struct ndt_conn_port	*port;
	struct work_struct	io_work;
	// struct nvmet_cq		nvme_cq;
	// struct nvmet_sq		nvme_sq;
	struct sk_buff_head	receive_queue;
	/* send state */
	// struct nvmet_tcp_cmd	*cmds;
	unsigned int		nr_cmds;
	struct list_head	free_list;
	struct llist_head	resp_list;
	struct list_head	resp_send_list;
	int			send_list_len;
	struct nvmet_tcp_cmd	*snd_cmd;

	/* recv state */
	int			offset;
	int			left;
	enum ndt_conn_recv_state rcv_state;
	// struct nvmet_tcp_cmd	*cmd;
	// union nvme_tcp_pdu	pdu;
	struct vs_hdr vs_hdr;
	/* digest state */
	bool			hdr_digest;
	bool			data_digest;
	struct ahash_request	*snd_hash;
	struct ahash_request	*rcv_hash;

	spinlock_t		state_lock;
	enum ndt_conn_queue_state state;

	struct sockaddr_storage	sockaddr;
	struct sockaddr_storage	sockaddr_peer;
	struct work_struct	release_work;

	int			idx;
	struct list_head	queue_list;

	// struct nvmet_tcp_cmd	connect;

	struct page_frag_cache	pf_cache;

	void (*data_ready)(struct sock *);
	void (*state_change)(struct sock *);
	void (*write_space)(struct sock *);
};

void ndt_conn_remove_port(struct ndt_conn_port *port);
int ndt_conn_alloc_queue(struct ndt_conn_port *port,
		struct socket *newsock);
void ndt_conn_io_work(struct work_struct *w);
int ndt_conn_set_queue_sock(struct ndt_conn_queue *queue);
void ndt_conn_state_change(struct sock *sk);
void ndt_conn_write_space(struct sock *sk);
void ndt_conn_data_ready(struct sock *sk);
int ndt_init_conn_port(struct ndt_conn_port *port);
void ndt_conn_listen_data_ready(struct sock *sk);
void ndt_conn_accept_work(struct work_struct *w);
void ndt_conn_schedule_release_queue(struct ndt_conn_queue *queue);
void ndt_conn_release_queue_work(struct work_struct *w);
void ndt_conn_restore_socket_callbacks(struct ndt_conn_queue *queue);
int __init ndt_conn_init(void);
void __exit ndt_conn_exit(void);

#endif /* _ND_TARGET_H */
