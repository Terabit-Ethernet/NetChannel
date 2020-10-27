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

/* assign */
static int nd_tcp_add_port(char* local_ip, char* local_port)
{
	struct nd_conn_port *port;
	__kernel_sa_family_t af;
	int ret;

	port = kzalloc(sizeof(*port), GFP_KERNEL);
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
	INIT_WORK(&port->accept_work, nd_tcp_accept_work);
	if (port->nport->inline_data_size < 0)
		port->nport->inline_data_size = NVMET_TCP_DEF_INLINE_DATA_SIZE;

	ret = sock_create(port->addr.ss_family, SOCK_STREAM,
				IPPROTO_TCP, &port->sock);
	if (ret) {
		pr_err("failed to create a socket\n");
		goto err_port;
	}

	port->sock->sk->sk_user_data = port;
	port->data_ready = port->sock->sk->sk_data_ready;
	port->sock->sk->sk_data_ready = nvmet_tcp_listen_data_ready;
	sock_set_reuseaddr(port->sock->sk);
	tcp_sock_set_nodelay(port->sock->sk);
	if (so_priority > 0)
		sock_set_priority(port->sock->sk, so_priority);

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

	nport->priv = port;
	pr_info("enabling port %d (%pISpc)\n",
		le16_to_cpu(nport->disc_addr.portid), &port->addr);

	return 0;

err_sock:
	sock_release(port->sock);
err_port:
	kfree(port);
	return ret;
}

static void nvmet_tcp_accept_work(struct work_struct *w)
{
	struct nvmet_tcp_port *port =
		container_of(w, struct nvmet_tcp_port, accept_work);
	struct socket *newsock;
	int ret;

	while (true) {
		ret = kernel_accept(port->sock, &newsock, O_NONBLOCK);
		if (ret < 0) {
			if (ret != -EAGAIN)
				pr_warn("failed to accept err=%d\n", ret);
			return;
		}
		ret = nvmet_tcp_alloc_queue(port, newsock);
		if (ret) {
			pr_err("failed to allocate queue\n");
			sock_release(newsock);
		}
	}
}

static void nvmet_tcp_listen_data_ready(struct sock *sk)
{
	struct nd_conn_port *port;

	read_lock_bh(&sk->sk_callback_lock);
	port = sk->sk_user_data;
	if (!port)
		goto out;

	if (sk->sk_state == TCP_LISTEN)
		schedule_work(&port->accept_work);
out:
	read_unlock_bh(&sk->sk_callback_lock);
}
