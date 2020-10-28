#include "nd_target.h"
static DEFINE_IDA(ndt_conn_queue_ida);
static LIST_HEAD(ndt_conn_queue_list);
static DEFINE_MUTEX(ndt_conn_queue_mutex);

static struct workqueue_struct *ndt_conn_wq;

#define NDT_CONN_RECV_BUDGET		8
#define NDT_CONN_SEND_BUDGET		8
#define NDT_CONN_IO_WORK_BUDGET	64

static inline int queue_cpu(struct ndt_conn_queue *queue)
{
	return queue->sock->sk->sk_incoming_cpu;
}

void ndt_conn_schedule_release_queue(struct ndt_conn_queue *queue)
{
	spin_lock(&queue->state_lock);
	if (queue->state != NDT_TCP_Q_DISCONNECTING) {
		queue->state = NDT_TCP_Q_DISCONNECTING;
		schedule_work(&queue->release_work);
	}
	spin_unlock(&queue->state_lock);
}

void ndt_conn_accept_work(struct work_struct *w)
{
	struct ndt_conn_port *port =
		container_of(w, struct ndt_conn_port, accept_work);
	struct socket *newsock;
	int ret;

	while (true) {
		ret = kernel_accept(port->sock, &newsock, O_NONBLOCK);
		if (ret < 0) {
			if (ret != -EAGAIN)
				pr_warn("failed to accept err=%d\n", ret);
			return;
		}
		ret = ndt_conn_alloc_queue(port, newsock);
		if (ret) {
			pr_err("failed to allocate queue\n");
			sock_release(newsock);
		}
	}
}

void ndt_conn_listen_data_ready(struct sock *sk)
{
	struct ndt_conn_port *port;

	read_lock_bh(&sk->sk_callback_lock);
	port = sk->sk_user_data;
	if (!port)
		goto out;

	if (sk->sk_state == TCP_LISTEN)
		schedule_work(&port->accept_work);
out:
	read_unlock_bh(&sk->sk_callback_lock);
}

/* assign */
int ndt_init_tcp_port(struct ndt_conn_port *port)
{
	// struct ndt_conn_port *port;
	char* local_ip = port->local_ip;
	char* local_port = port->local_port;

	__kernel_sa_family_t af;
	int opt, ret;

	// port = kzalloc(sizeof(*port), GFP_KERNEL);
	if (!port)
		return -ENOMEM;

	// switch (nport->disc_addr.adrfam) {
	// case NVMF_ADDR_FAMILY_IP4:
		af = AF_INET;
	// 	break;
	// case NVMF_ADDR_FAMILY_IP6:
	// 	af = AF_INET6;
	// 	break;
	// default:
	// 	pr_err("address family %d not supported\n",
	// 			nport->disc_addr.adrfam);
	// 	ret = -EINVAL;
	// 	goto err_port;
	// }

	ret = inet_pton_with_scope(&init_net, af, local_ip,
			local_port, &port->addr);
	if (ret) {
		pr_err("malformed ip/port passed: %s:%s\n",
			local_ip, local_port);
		goto err_port;
	}

	// port->nport = nport;
	INIT_WORK(&port->accept_work, ndt_conn_accept_work);
	// if (port->nport->inline_data_size < 0)
	// 	port->nport->inline_data_size = NVMET_TCP_DEF_INLINE_DATA_SIZE;

	ret = sock_create(port->addr.ss_family, SOCK_STREAM,
				IPPROTO_TCP, &port->sock);
	if (ret) {
		pr_err("failed to create a socket\n");
		goto err_port;
	}

	port->sock->sk->sk_user_data = port;
	port->data_ready = port->sock->sk->sk_data_ready;
	port->sock->sk->sk_data_ready = ndt_conn_listen_data_ready;
	opt = 1;
	ret = kernel_setsockopt(port->sock, IPPROTO_TCP,
			TCP_NODELAY, (char *)&opt, sizeof(opt));
	if (ret) {
		pr_err("failed to set TCP_NODELAY sock opt %d\n", ret);
		goto err_sock;
	}

	ret = kernel_setsockopt(port->sock, SOL_SOCKET, SO_REUSEADDR,
			(char *)&opt, sizeof(opt));
	if (ret) {
		pr_err("failed to set SO_REUSEADDR sock opt %d\n", ret);
		goto err_sock;
	}
	// sock_set_reuseaddr(port->sock->sk);
	// tcp_sock_set_nodelay(port->sock->sk);
	// if (so_priority > 0)
	// 	sock_set_priority(port->sock->sk, so_priority);

	ret = kernel_bind(port->sock, (struct sockaddr *)&port->addr,
			sizeof(port->addr));
	if (ret) {
		pr_err("failed to bind port socket %d\n", ret);
		goto err_sock;
	}

	ret = kernel_listen(port->sock, 128);
	if (ret) {
		pr_err("failed to listen %d on port sock\n", ret);
		goto err_sock;
	}

	// nport->priv = port;
	pr_info("enabling port %s (%pISpc)\n",
		local_port, &port->addr);

	return 0;

err_sock:
	sock_release(port->sock);
err_port:
	// kfree(port);
	return ret;
}

void ndt_conn_release_queue_work(struct work_struct *w)
{
	struct ndt_conn_queue *queue =
		container_of(w, struct ndt_conn_queue, release_work);

	mutex_lock(&ndt_conn_queue_mutex);
	list_del_init(&queue->queue_list);
	mutex_unlock(&ndt_conn_queue_mutex);

	ndt_conn_restore_socket_callbacks(queue);
	flush_work(&queue->io_work);

	// nvmet_tcp_uninit_data_in_cmds(queue);
	// nvmet_sq_destroy(&queue->nvme_sq);
	cancel_work_sync(&queue->io_work);
	sock_release(queue->sock);
	// nvmet_tcp_free_cmds(queue);
	// if (queue->hdr_digest || queue->data_digest)
	// 	nvmet_tcp_free_crypto(queue);
	ida_simple_remove(&ndt_conn_queue_ida, queue->idx);

	kfree(queue);
}

void ndt_conn_restore_socket_callbacks(struct ndt_conn_queue *queue)
{
	struct socket *sock = queue->sock;

	write_lock_bh(&sock->sk->sk_callback_lock);
	sock->sk->sk_data_ready =  queue->data_ready;
	sock->sk->sk_state_change = queue->state_change;
	sock->sk->sk_write_space = queue->write_space;
	sock->sk->sk_user_data = NULL;
	write_unlock_bh(&sock->sk->sk_callback_lock);
}

void ndt_conn_data_ready(struct sock *sk)
{
	struct ndt_conn_queue *queue;

	read_lock_bh(&sk->sk_callback_lock);
	queue = sk->sk_user_data;
	if (likely(queue))
		queue_work_on(queue_cpu(queue), ndt_conn_wq, &queue->io_work);
	read_unlock_bh(&sk->sk_callback_lock);
}

void ndt_conn_write_space(struct sock *sk)
{
	struct ndt_conn_queue *queue;

	read_lock_bh(&sk->sk_callback_lock);
	queue = sk->sk_user_data;
	if (unlikely(!queue))
		goto out;

	if (unlikely(queue->state == NDT_TCP_Q_CONNECTING)) {
		queue->write_space(sk);
		goto out;
	}

	if (sk_stream_is_writeable(sk)) {
		clear_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		queue_work_on(queue_cpu(queue), ndt_conn_wq, &queue->io_work);
	}
out:
	read_unlock_bh(&sk->sk_callback_lock);
}

void ndt_conn_state_change(struct sock *sk)
{
	struct ndt_conn_queue *queue;

	write_lock_bh(&sk->sk_callback_lock);
	queue = sk->sk_user_data;
	if (!queue)
		goto done;

	switch (sk->sk_state) {
	case TCP_FIN_WAIT1:
	case TCP_CLOSE_WAIT:
	case TCP_CLOSE:
		/* FALLTHRU */
		sk->sk_user_data = NULL;
		ndt_conn_schedule_release_queue(queue);
		break;
	default:
		pr_warn("queue %d unhandled state %d\n",
			queue->idx, sk->sk_state);
	}
done:
	write_unlock_bh(&sk->sk_callback_lock);
}

void ndt_prepare_receive_pkts(struct ndt_conn_queue *queue)
{
	queue->offset = 0;
	// this part needed to be modified
	// queue->left = sizeof(struct tcp_hdr);
	// queue->cmd = NULL;
	queue->rcv_state = NDT_TCP_RECV_PDU;
}


int ndt_conn_set_queue_sock(struct ndt_conn_queue *queue)
{
	struct socket *sock = queue->sock;
	struct inet_sock *inet = inet_sk(sock->sk);
	struct linger sol = { .l_onoff = 1, .l_linger = 0 };
	int ret;

	ret = kernel_getsockname(sock,
		(struct sockaddr *)&queue->sockaddr);
	if (ret < 0)
		return ret;

	ret = kernel_getpeername(sock,
		(struct sockaddr *)&queue->sockaddr_peer);
	if (ret < 0)
		return ret;

	/*
	 * Cleanup whatever is sitting in the TCP transmit queue on socket
	 * close. This is done to prevent stale data from being sent should
	 * the network connection be restored before TCP times out.
	 */
	ret = kernel_setsockopt(sock, SOL_SOCKET, SO_LINGER,
		(char *)&sol, sizeof(sol));
	if (ret)
		return ret;

	// if (so_priority > 0)
	// 	sock_set_priority(sock->sk, so_priority);

	/* Set socket type of service */
	if (inet->rcv_tos > 0) {
		int tos = inet->rcv_tos;

		ret = kernel_setsockopt(sock, SOL_IP, IP_TOS,
				(char *)&tos, sizeof(tos));
		if (ret)
			return ret;
	}

	write_lock_bh(&sock->sk->sk_callback_lock);
	sock->sk->sk_user_data = queue;
	queue->data_ready = sock->sk->sk_data_ready;
	sock->sk->sk_data_ready = ndt_conn_data_ready;
	queue->state_change = sock->sk->sk_state_change;
	sock->sk->sk_state_change = ndt_conn_state_change;
	queue->write_space = sock->sk->sk_write_space;
	sock->sk->sk_write_space = ndt_conn_write_space;
	write_unlock_bh(&sock->sk->sk_callback_lock);

	return 0;
}

void ndt_conn_io_work(struct work_struct *w)
{
	// struct ndt_conn_queue *queue =
	// 	container_of(w, struct ndt_conn_queue, io_work);
	// bool pending;
	// int ret, ops = 0;

	// do {
	// 	pending = false;

	// 	ret = nvmet_tcp_try_recv(queue, NDT_CONN_RECV_BUDGET, &ops);
	// 	if (ret > 0)
	// 		pending = true;
	// 	else if (ret < 0)
	// 		return;

	// 	ret = nvmet_tcp_try_send(queue, NDT_CON_SEND_BUDGET, &ops);
	// 	if (ret > 0)
	// 		pending = true;
	// 	else if (ret < 0)
	// 		return;

	// } while (pending && ops < NDT_CONN_IO_WORK_BUDGET);

	// /*
	//  * We exahusted our budget, requeue our selves
	//  */
	// if (pending)
	// 	queue_work_on(queue_cpu(queue), ndt_conn_wq, &queue->io_work);
}

int ndt_conn_alloc_queue(struct ndt_conn_port *port,
		struct socket *newsock)
{
	struct ndt_conn_queue *queue;
	int ret;

	queue = kzalloc(sizeof(*queue), GFP_KERNEL);
	if (!queue)
		return -ENOMEM;

	INIT_WORK(&queue->release_work, ndt_conn_release_queue_work);
	INIT_WORK(&queue->io_work, ndt_conn_io_work);
	queue->sock = newsock;
	queue->port = port;
	// queue->nr_cmds = 0;
	spin_lock_init(&queue->state_lock);
	queue->state = NDT_TCP_Q_CONNECTING;
	INIT_LIST_HEAD(&queue->free_list);
	init_llist_head(&queue->resp_list);
	INIT_LIST_HEAD(&queue->resp_send_list);

	queue->idx = ida_simple_get(&ndt_conn_queue_ida, 0, 0, GFP_KERNEL);
	if (queue->idx < 0) {
		ret = queue->idx;
		goto out_free_queue;
	}

	// ret = nvmet_tcp_alloc_cmd(queue, &queue->connect);
	// if (ret)
	// 	goto out_ida_remove;

	// ret = nvmet_sq_init(&queue->nvme_sq);
	// if (ret)
	// 	goto out_free_connect;

	ndt_prepare_receive_pkts(queue);

	mutex_lock(&ndt_conn_queue_mutex);
	list_add_tail(&queue->queue_list, &ndt_conn_queue_list);
	mutex_unlock(&ndt_conn_queue_mutex);

	ret = ndt_conn_set_queue_sock(queue);
	if (ret)
		goto out_destroy_sq;

	queue_work_on(queue_cpu(queue), ndt_conn_wq, &queue->io_work);

	return 0;
out_destroy_sq:
	mutex_lock(&ndt_conn_queue_mutex);
	list_del_init(&queue->queue_list);
	mutex_unlock(&ndt_conn_queue_mutex);
	// nvmet_sq_destroy(&queue->nvme_sq);
// out_free_connect:
	// nvmet_tcp_free_cmd(&queue->connect);
// out_ida_remove:
	ida_simple_remove(&ndt_conn_queue_ida, queue->idx);
out_free_queue:
	kfree(queue);
	return ret;
}

void ndt_conn_remove_port(struct ndt_conn_port *port)
{
	// struct nvmet_tcp_port *port = nport->priv;
	write_lock_bh(&port->sock->sk->sk_callback_lock);
	port->sock->sk->sk_data_ready = port->data_ready;
	port->sock->sk->sk_user_data = NULL;
	write_unlock_bh(&port->sock->sk->sk_callback_lock);
	cancel_work_sync(&port->accept_work);

	sock_release(port->sock);
	kfree(port);
}

int __init ndt_conn_init(void)
{
	int ret;

	ndt_conn_wq = alloc_workqueue("ndt_conn_wq", WQ_HIGHPRI, 0);
	if (!ndt_conn_wq)
		return -ENOMEM;

	// ret = nvmet_register_transport(&nvmet_tcp_ops);
	// if (ret)
	// 	goto err;

	return 0;
// err:
	destroy_workqueue(ndt_conn_wq);
	return ret;
}

void __exit ndt_conn_exit(void)
{
	struct ndt_conn_queue *queue;

	// nvmet_unregister_transport(&nvmet_tcp_ops);

	flush_scheduled_work();
	mutex_lock(&ndt_conn_queue_mutex);
	list_for_each_entry(queue, &ndt_conn_queue_list, queue_list)
		kernel_sock_shutdown(queue->sock, SHUT_RDWR);
	mutex_unlock(&ndt_conn_queue_mutex);
	flush_scheduled_work();

	destroy_workqueue(ndt_conn_wq);
}