// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Support for INET connection oriented protocols.
 *
 * Authors:	See the TCP sources
 */

#include <linux/module.h>
#include <linux/jhash.h>

#include <net/inet_connection_sock.h>
#include <net/inet_hashtables.h>
#include <net/inet_timewait_sock.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/tcp_states.h>
#include <net/xfrm.h>
// #include <net/tcp.h>
#include <net/sock_reuseport.h>
#include <net/addrconf.h>
#include "nd_host.h"
// #include "linux_nd.h"
#include "nd_impl.h"
#include "nd_hashtables.h"


static void set_max_grant_batch(struct dst_entry *dst, struct nd_sock* dsk) {
	int bufs_per_gso, mtu, max_pkt_data, gso_size, max_gso_data;
	int num_gso_per_bdp;
	mtu = dst_mtu(dst);
	gso_size = dst->dev->gso_max_size;
	/* we assume BDP is larger than max_gso_data for now */
	// if (gso_size > nd_params.bdp)
	// 	gso_size = nd_params.bdp;
	// if (gso_size > nd_params.gso_size)
	// 	gso_size = nd_params.gso_size;
	bufs_per_gso = gso_size / mtu;
	max_pkt_data = mtu - sizeof(struct iphdr) - sizeof(struct nd_data_hdr);
	max_gso_data = bufs_per_gso * max_pkt_data;
	// gso_size = bufs_per_gso * mtu;
	num_gso_per_bdp = DIV_ROUND_UP(nd_params.bdp, max_gso_data);
	// dsk->receiver.max_gso_data = max_gso_data;
	// dsk->receiver.max_grant_batch = num_gso_per_bdp * max_gso_data;
}

void reqsk_queue_alloc(struct request_sock_queue *queue)
{
	spin_lock_init(&queue->rskq_lock);

	spin_lock_init(&queue->fastopenq.lock);
	queue->fastopenq.rskq_rst_head = NULL;
	queue->fastopenq.rskq_rst_tail = NULL;
	queue->fastopenq.qlen = 0;

	queue->rskq_accept_head = NULL;
}


#if IS_ENABLED(CONFIG_IPV6)
/* match_wildcard == true:  IPV6_ADDR_ANY equals to any IPv6 addresses if IPv6
 *                          only, and any IPv4 addresses if not IPv6 only
 * match_wildcard == false: addresses must be exactly the same, i.e.
 *                          IPV6_ADDR_ANY only equals to IPV6_ADDR_ANY,
 *                          and 0.0.0.0 equals to 0.0.0.0 only
 */
static bool ipv6_rcv_saddr_equal(const struct in6_addr *sk1_rcv_saddr6,
				 const struct in6_addr *sk2_rcv_saddr6,
				 __be32 sk1_rcv_saddr, __be32 sk2_rcv_saddr,
				 bool sk1_ipv6only, bool sk2_ipv6only,
				 bool match_wildcard)
{
	int addr_type = ipv6_addr_type(sk1_rcv_saddr6);
	int addr_type2 = sk2_rcv_saddr6 ? ipv6_addr_type(sk2_rcv_saddr6) : IPV6_ADDR_MAPPED;

	/* if both are mapped, treat as IPv4 */
	if (addr_type == IPV6_ADDR_MAPPED && addr_type2 == IPV6_ADDR_MAPPED) {
		if (!sk2_ipv6only) {
			if (sk1_rcv_saddr == sk2_rcv_saddr)
				return true;
			if (!sk1_rcv_saddr || !sk2_rcv_saddr)
				return match_wildcard;
		}
		return false;
	}

	if (addr_type == IPV6_ADDR_ANY && addr_type2 == IPV6_ADDR_ANY)
		return true;

	if (addr_type2 == IPV6_ADDR_ANY && match_wildcard &&
	    !(sk2_ipv6only && addr_type == IPV6_ADDR_MAPPED))
		return true;

	if (addr_type == IPV6_ADDR_ANY && match_wildcard &&
	    !(sk1_ipv6only && addr_type2 == IPV6_ADDR_MAPPED))
		return true;

	if (sk2_rcv_saddr6 &&
	    ipv6_addr_equal(sk1_rcv_saddr6, sk2_rcv_saddr6))
		return true;

	return false;
}
#endif

/* match_wildcard == true:  0.0.0.0 equals to any IPv4 addresses
 * match_wildcard == false: addresses must be exactly the same, i.e.
 *                          0.0.0.0 only equals to 0.0.0.0
 */
static bool ipv4_rcv_saddr_equal(__be32 sk1_rcv_saddr, __be32 sk2_rcv_saddr,
				 bool sk2_ipv6only, bool match_wildcard)
{
	if (!sk2_ipv6only) {
		if (sk1_rcv_saddr == sk2_rcv_saddr)
			return true;
		if (!sk1_rcv_saddr || !sk2_rcv_saddr)
			return match_wildcard;
	}
	return false;
}

void inet_sk_state_store(struct sock *sk, int newstate)
{
	// trace_inet_sock_set_state(sk, sk->sk_state, newstate);
	smp_store_release(&sk->sk_state, newstate);
}


void nd_set_state(struct sock* sk, int state) {
	
	switch (state) {
	case ND_ESTABLISH:
			// TCP_INC_STATS(sock_net(sk), TCP_MIB_CURRESTAB);
		// break;
	// case ND_SENDER:
		break;
	case TCP_CLOSE:
		// if (oldstate == TCP_CLOSE_WAIT || oldstate == TCP_ESTABLISHED)
		// 	TCP_INC_STATS(sock_net(sk), TCP_MIB_ESTABRESETS);
		sk->sk_prot->unhash(sk);
		/* !(sk->sk_userlocks & SOCK_BINDPORT_LOCK) may need later*/
		if (nd_sk(sk)->icsk_bind_hash) {
			// printk("put port\n");
			nd_put_port(sk);
		} else {
			// printk("userlook and SOCK_BINDPORT_LOCK:%d\n", !(sk->sk_userlocks & SOCK_BINDPORT_LOCK));
			// printk("cannot put port\n");
		}
		/* fall through */
	default:
		// if (oldstate == TCP_ESTABLISHED)
			// TCP_DEC_STATS(sock_net(sk), TCP_MIB_CURRESTAB);
		break;
	}
	inet_sk_state_store(sk, state);
}
// bool inet_rcv_saddr_equal(const struct sock *sk, const struct sock *sk2,
// 			  bool match_wildcard)
// {
// #if IS_ENABLED(CONFIG_IPV6)
// 	if (sk->sk_family == AF_INET6)
// 		return ipv6_rcv_saddr_equal(&sk->sk_v6_rcv_saddr,
// 					    inet6_rcv_saddr(sk2),
// 					    sk->sk_rcv_saddr,
// 					    sk2->sk_rcv_saddr,
// 					    ipv6_only_sock(sk),
// 					    ipv6_only_sock(sk2),
// 					    match_wildcard);
// #endif
// 	return ipv4_rcv_saddr_equal(sk->sk_rcv_saddr, sk2->sk_rcv_saddr,
// 				    ipv6_only_sock(sk2), match_wildcard);
// }
// EXPORT_SYMBOL(inet_rcv_saddr_equal);

// bool inet_rcv_saddr_any(const struct sock *sk)
// {
// #if IS_ENABLED(CONFIG_IPV6)
// 	if (sk->sk_family == AF_INET6)
// 		return ipv6_addr_any(&sk->sk_v6_rcv_saddr);
// #endif
// 	return !sk->sk_rcv_saddr;
// }
// EXPORT_SYMBOL(inet_rcv_saddr_any);

// void inet_get_local_port_range(struct net *net, int *low, int *high)
// {
// 	unsigned int seq;

// 	do {
// 		seq = read_seqbegin(&net->ipv4.ip_local_ports.lock);

// 		*low = net->ipv4.ip_local_ports.range[0];
// 		*high = net->ipv4.ip_local_ports.range[1];
// 	} while (read_seqretry(&net->ipv4.ip_local_ports.lock, seq));
// }
// EXPORT_SYMBOL(inet_get_local_port_range);

static int nd_sk_bind_conflict(const struct sock *sk,
				  const struct inet_bind_bucket *tb,
				  bool relax, bool reuseport_ok)
{
	struct sock *sk2;
	bool reuse = sk->sk_reuse;
	bool reuseport = !!sk->sk_reuseport && reuseport_ok;
	// kuid_t uid = sock_i_uid((struct sock *)sk);

	/*
	 * Unlike other sk lookup places we do not check
	 * for sk_net here, since _all_ the socks listed
	 * in tb->owners list belong to the same net - the
	 * one this bucket belongs to.
	 */
	sk_for_each_bound(sk2, &tb->owners) {
		if (sk != sk2 &&
		    (!sk->sk_bound_dev_if ||
		     !sk2->sk_bound_dev_if ||
		     sk->sk_bound_dev_if == sk2->sk_bound_dev_if)) {
			if ((!reuse || !sk2->sk_reuse ||
			    sk2->sk_state == ND_LISTEN) &&
			    (!reuseport || !sk2->sk_reuseport ||
			     rcu_access_pointer(sk->sk_reuseport_cb))) {
				if (inet_rcv_saddr_equal(sk, sk2, true))
					break;
			}
			if (!relax && reuse && sk2->sk_reuse &&
			    sk2->sk_state != ND_LISTEN) {
				if (inet_rcv_saddr_equal(sk, sk2, true))
					break;
			}
		}

	}

	return sk2 != NULL;
}

/*
 * Find an open port number for the socket.  Returns with the
 * inet_bind_hashbucket lock held.
 */
static struct inet_bind_hashbucket *
nd_sk_find_open_port(struct sock *sk, struct inet_bind_bucket **tb_ret, int *port_ret)
{
	struct inet_hashinfo *hinfo = sk->sk_prot->h.hashinfo;
	int port = 0;
	struct inet_bind_hashbucket *head;
	struct net *net = sock_net(sk);
	int i, low, high, attempt_half;
	struct inet_bind_bucket *tb;
	u32 remaining, offset;
	int l3mdev;

	l3mdev = inet_sk_bound_l3mdev(sk);
	attempt_half = (sk->sk_reuse == SK_CAN_REUSE) ? 1 : 0;
other_half_scan:
	inet_get_local_port_range(net, &low, &high);
	high++; /* [32768, 60999] -> [32768, 61000[ */
	if (high - low < 4)
		attempt_half = 0;
	if (attempt_half) {
		int half = low + (((high - low) >> 2) << 1);

		if (attempt_half == 1)
			high = half;
		else
			low = half;
	}
	remaining = high - low;
	if (likely(remaining > 1))
		remaining &= ~1U;

	offset = prandom_u32() % remaining;
	/* __inet_hash_connect() favors ports having @low parity
	 * We do the opposite to not pollute connect() users.
	 */
	offset |= 1U;

other_parity_scan:
	port = low + offset;
	for (i = 0; i < remaining; i += 2, port += 2) {
		if (unlikely(port >= high))
			port -= remaining;
		if (inet_is_local_reserved_port(net, port))
			continue;
		head = &hinfo->bhash[inet_bhashfn(net, port,
						  hinfo->bhash_size)];
		spin_lock_bh(&head->lock);
		inet_bind_bucket_for_each(tb, &head->chain)
			if (net_eq(ib_net(tb), net) && tb->l3mdev == l3mdev &&
			    tb->port == port) {
				if (!nd_sk_bind_conflict(sk, tb, false, false))
					goto success;
				goto next_port;
			}
		tb = NULL;
		goto success;
next_port:

		spin_unlock_bh(&head->lock);
		cond_resched();
	}

	offset--;
	if (!(offset & 1))
		goto other_parity_scan;

	if (attempt_half == 1) {
		/* OK we now try the upper half of the range */
		attempt_half = 2;
		goto other_half_scan;
	}
	return NULL;
success:
	*port_ret = port;
	*tb_ret = tb;
	return head;
}

static inline int sk_reuseport_match(struct inet_bind_bucket *tb,
				     struct sock *sk)
{
	kuid_t uid = sock_i_uid(sk);

	if (tb->fastreuseport <= 0)
		return 0;
	if (!sk->sk_reuseport)
		return 0;
	if (rcu_access_pointer(sk->sk_reuseport_cb))
		return 0;
	if (!uid_eq(tb->fastuid, uid))
		return 0;
	/* We only need to check the rcv_saddr if this tb was once marked
	 * without fastreuseport and then was reset, as we can only know that
	 * the fast_*rcv_saddr doesn't have any conflicts with the socks on the
	 * owners list.
	 */
	if (tb->fastreuseport == FASTREUSEPORT_ANY)
		return 1;
#if IS_ENABLED(CONFIG_IPV6)
	if (tb->fast_sk_family == AF_INET6)
		return ipv6_rcv_saddr_equal(&tb->fast_v6_rcv_saddr,
					    inet6_rcv_saddr(sk),
					    tb->fast_rcv_saddr,
					    sk->sk_rcv_saddr,
					    tb->fast_ipv6_only,
					    ipv6_only_sock(sk), true);
#endif
	return ipv4_rcv_saddr_equal(tb->fast_rcv_saddr, sk->sk_rcv_saddr,
				    ipv6_only_sock(sk), true);
}

/* Obtain a reference to a local port for the given sock,
 * if snum is zero it means select any available local port.
 * We try to allocate an odd port (and leave even ports for connect())
 */
int nd_sk_get_port(struct sock *sk, unsigned short snum)
{
	bool reuse = sk->sk_reuse && sk->sk_state != ND_LISTEN;
	struct inet_hashinfo *hinfo = sk->sk_prot->h.hashinfo;
	int ret = 1, port = snum;
	struct inet_bind_hashbucket *head;
	struct net *net = sock_net(sk);
	struct inet_bind_bucket *tb = NULL;
	kuid_t uid = sock_i_uid(sk);
	int l3mdev;
	l3mdev = inet_sk_bound_l3mdev(sk);
	if (!port) {
		head = nd_sk_find_open_port(sk, &tb, &port);
		if (!head)
			return ret;
		if (!tb)
			goto tb_not_found;
		goto success;
	}
	head = &hinfo->bhash[inet_bhashfn(net, port,
					  hinfo->bhash_size)];

	spin_lock_bh(&head->lock);
	inet_bind_bucket_for_each(tb, &head->chain)
		if (net_eq(ib_net(tb), net) && tb->l3mdev == l3mdev &&
		    tb->port == port)
			goto tb_found;
tb_not_found:
	tb = inet_bind_bucket_create(hinfo->bind_bucket_cachep,
				     net, head, port, l3mdev);

	if (!tb)
		goto fail_unlock;
tb_found:
	if (!hlist_empty(&tb->owners)) {
		if (sk->sk_reuse == SK_FORCE_REUSE)
			goto success;

		if ((tb->fastreuse > 0 && reuse) ||
		    sk_reuseport_match(tb, sk))
			goto success;

		if (nd_sk_bind_conflict(sk, tb, true, true))
			goto fail_unlock;

	}
success:
	if (hlist_empty(&tb->owners)) {
		tb->fastreuse = reuse;
		if (sk->sk_reuseport) {
			tb->fastreuseport = FASTREUSEPORT_ANY;
			tb->fastuid = uid;
			tb->fast_rcv_saddr = sk->sk_rcv_saddr;
			tb->fast_ipv6_only = ipv6_only_sock(sk);
			tb->fast_sk_family = sk->sk_family;
#if IS_ENABLED(CONFIG_IPV6)
			tb->fast_v6_rcv_saddr = sk->sk_v6_rcv_saddr;
#endif
		} else {
			tb->fastreuseport = 0;
		}
	} else {
		if (!reuse)
			tb->fastreuse = 0;
		if (sk->sk_reuseport) {
			/* We didn't match or we don't have fastreuseport set on
			 * the tb, but we have sk_reuseport set on this socket
			 * and we know that there are no bind conflicts with
			 * this socket in this tb, so reset our tb's reuseport
			 * settings so that any subsequent sockets that match
			 * our current socket will be put on the fast path.
			 *
			 * If we reset we need to set FASTREUSEPORT_STRICT so we
			 * do extra checking for all subsequent sk_reuseport
			 * socks.
			 */
			if (!sk_reuseport_match(tb, sk)) {
				tb->fastreuseport = FASTREUSEPORT_STRICT;
				tb->fastuid = uid;
				tb->fast_rcv_saddr = sk->sk_rcv_saddr;
				tb->fast_ipv6_only = ipv6_only_sock(sk);
				tb->fast_sk_family = sk->sk_family;
#if IS_ENABLED(CONFIG_IPV6)
				tb->fast_v6_rcv_saddr = sk->sk_v6_rcv_saddr;
#endif
			}
		} else {
			tb->fastreuseport = 0;
		}
	}
	if (!nd_sk(sk)->icsk_bind_hash)
		inet_bind_hash(sk, tb, port);
	WARN_ON(nd_sk(sk)->icsk_bind_hash != tb);
	ret = 0;

fail_unlock:

	spin_unlock_bh(&head->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(nd_sk_get_port);


int nd_wait_for_connect(struct sock *sk, long *timeo_p)
{
	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	struct task_struct *tsk = current;
	int done;

	do {
		int err = sock_error(sk);
		if (err)
			return err;
		if ((1 << sk->sk_state) & ~(NDF_SYNC_SENT))
			return -EPIPE;
		if (!*timeo_p)
			return -EAGAIN;
		if (signal_pending(tsk))
			return sock_intr_errno(*timeo_p);

		add_wait_queue(sk_sleep(sk), &wait);
		sk->sk_write_pending++;
		done = sk_wait_event(sk, timeo_p,
				     !sk->sk_err &&
				     !((1 << sk->sk_state) &
				       ~(NDF_ESTABLISH)), &wait);
		remove_wait_queue(sk_sleep(sk), &wait);
		sk->sk_write_pending--;
	} while (!done);
	return 0;
}
/* this function is copied from inet_wait_for_connect */
// long nd_wait_for_connect(struct sock *sk, long timeo, int writebias)
// {
// 	DEFINE_WAIT_FUNC(wait, woken_wake_function);

// 	add_wait_queue(sk_sleep(sk), &wait);
// 	sk->sk_write_pending += writebias;

// 	/* Basic assumption: if someone sets sk->sk_err, he _must_
// 	 * change state of the socket from TCP_SYN_*.
// 	 * Connect() does not allow to get error notifications
// 	 * without closing the socket.
// 	 */
// 	while ((1 << sk->sk_state) & (NDF_SYNC_SENT)) {
// 		release_sock(sk);
// 		timeo = wait_woken(&wait, TASK_INTERRUPTIBLE, timeo);
// 		lock_sock(sk);
// 		if (signal_pending(current) || !timeo)
// 			break;
// 	}
// 	remove_wait_queue(sk_sleep(sk), &wait);
// 	sk->sk_write_pending -= writebias;
// 	return timeo;
// }

/* This will initiate an outgoing connection. */
int nd_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	// struct nd_sock *dsk = nd_sk(sk);
	struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
	struct inet_sock *inet = inet_sk(sk);
	// struct nd_sock *tp = nd_sk(sk);
	__be16 orig_sport, orig_dport;
	__be32 daddr, nexthop;
	struct flowi4 *fl4;
	struct rtable *rt;
	int err;
	uint32_t flow_len;
	struct ip_options_rcu *inet_opt;
	// struct inet_timewait_death_row *tcp_death_row = &sock_net(sk)->ipv4.tcp_death_row;
	flow_len = (uint32_t)usin->sin_zero[0] << 24 |
      (uint32_t)usin->sin_zero[1] << 16 |
      (uint32_t)usin->sin_zero[2] << 8  |
      (uint32_t)usin->sin_zero[3];	
    WARN_ON(sk->sk_state != TCP_CLOSE);
    if (addr_len < sizeof(struct sockaddr_in))
		return -EINVAL;

	if (usin->sin_family != AF_INET)
		return -EAFNOSUPPORT;

	nexthop = daddr = usin->sin_addr.s_addr;
	inet_opt = rcu_dereference_protected(inet->inet_opt,
					     lockdep_sock_is_held(sk));
	if (inet_opt && inet_opt->opt.srr) {
		if (!daddr)
			return -EINVAL;
		nexthop = inet_opt->opt.faddr;
	}

	orig_sport = inet->inet_sport;
	orig_dport = usin->sin_port;
	fl4 = &inet->cork.fl.u.ip4;
	rt = ip_route_connect(fl4, nexthop, inet->inet_saddr,
			      RT_CONN_FLAGS(sk), sk->sk_bound_dev_if,
			      IPPROTO_VIRTUAL_SOCK,
			      orig_sport, orig_dport, sk);
	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		if (err == -ENETUNREACH)
			IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTNOROUTES);
		return err;
	}

	if (rt->rt_flags & (RTCF_MULTICAST | RTCF_BROADCAST)) {
		ip_rt_put(rt);
		return -ENETUNREACH;
	}

	if (!inet_opt || !inet_opt->opt.srr)
		daddr = fl4->daddr;

	// set source address
	if (!inet->inet_saddr)
		inet->inet_saddr = fl4->saddr;
	sk_rcv_saddr_set(sk, inet->inet_saddr);

	// if (tp->rx_opt.ts_recent_stamp && inet->inet_daddr != daddr) {
	// 	/* Reset inherited state */
	// 	tp->rx_opt.ts_recent	   = 0;
	// 	tp->rx_opt.ts_recent_stamp = 0;
	// 	if (likely(!tp->repair))
	// 		WRITE_ONCE(tp->write_seq, 0);
	// }

	// set dest port and address
	inet->inet_dport = usin->sin_port;
	sk_daddr_set(sk, daddr);

	// inet_csk(sk)->icsk_ext_hdr_len = 0;
	// if (inet_opt)
	// 	inet_csk(sk)->icsk_ext_hdr_len = inet_opt->opt.optlen;

	// tp->rx_opt.mss_clamp = TCP_MSS_DEFAULT;

	/* Socket identity is still unknown (sport may be zero).
	 * However we set state to SYN-SENT and not releasing socket
	 * lock select source port, enter ourselves into the hash tables and
	 * complete initialization after this.
	 */
	// source port is decided by bind; if not, set in hash_connect
	err = nd_hash_connect(sk);
	if (err)
		goto failure;

	sk_set_txhash(sk);

	rt = ip_route_newports(fl4, rt, orig_sport, orig_dport,
			       inet->inet_sport, inet->inet_dport, sk);
	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		rt = NULL;
		goto failure;
	}
	/* OK, now commit destination to socket.  */
	sk->sk_gso_type = SKB_GSO_TCPV4;
	/*set gso capacity */
	sk_setup_caps(sk, &rt->dst);
	/* set dst */
	if (dst_hold_safe(&rt->dst)) {
		sk->sk_rx_dst = &rt->dst;
		inet_sk(sk)->rx_dst_ifindex = rt->rt_iif;
	}
	rt = NULL;

	// if (likely(!tp->repair)) {
	// 	if (!tp->write_seq)
	// 		WRITE_ONCE(tp->write_seq,
	// 			   secure_tcp_seq(inet->inet_saddr,
	// 					  inet->inet_daddr,
	// 					  inet->inet_sport,
	// 					  usin->sin_port));
	// 	tp->tsoffset = secure_tcp_ts_off(sock_net(sk),
	// 					 inet->inet_saddr,
	// 					 inet->inet_daddr);
	// }

	inet->inet_id = prandom_u32();

	// if (tcp_fastopen_defer_connect(sk, &err))
	// 	return err;
	// if (err)
	// 	goto failure;

	// err = tcp_connect(sk);

	// send notification pkt
	// if(!dsk->peer)
	// 	dsk->peer = nd_peer_find(&nd_peers_table, daddr, inet);
	/* send sync request */
    nd_conn_queue_request(construct_sync_req(sk), true, true);
	nd_set_state(sk, ND_SYNC_SENT);

	// nd_xmit_control(construct_sync_pkt(sk, 0, flow_len, 0), sk, inet->inet_dport); 
	// dsk->total_length = flow_len;
	// if (err)
	// 	goto failure;

	return 0;

failure:
	/*
	 * This unhashes the socket and releases the local port,
	 * if necessary.
	 */
	nd_set_state(sk, TCP_CLOSE);
	ip_rt_put(rt);
	sk->sk_route_caps = 0;
	inet->inet_dport = 0;
	// inet->inet_sport = 0;
	return err;
}
EXPORT_SYMBOL(nd_v4_connect);


int nd_listen_start(struct sock *sk, int backlog)
{
	struct nd_sock *dsk = nd_sk(sk);
	struct inet_sock *inet = inet_sk(sk);
	int err = -EADDRINUSE;

	reqsk_queue_alloc(&dsk->icsk_accept_queue);

	sk->sk_ack_backlog = 0;
	// inet_csk_delack_init(sk);

	/* There is race window here: we announce ourselves listening,
	 * but this transition is still not validated by get_port().
	 * It is OK, because this socket enters to hash table only
	 * after validation is complete.
	 */
	inet_sk_state_store(sk, ND_LISTEN);
	if (!sk->sk_prot->get_port(sk, inet->inet_num)) {
		inet->inet_sport = htons(inet->inet_num);

		sk_dst_reset(sk);
		err = sk->sk_prot->hash(sk);

		if (likely(!err))
			return 0;
	}

	inet_sk_set_state(sk, TCP_CLOSE);
	return err;
}
EXPORT_SYMBOL_GPL(nd_listen_start);

/*
 *	Move a socket into listening state.
 */
int nd_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	unsigned char old_state;
	int err;

	lock_sock(sk);

	err = -EINVAL;

	if (sock->state != SS_UNCONNECTED || sock->type != SOCK_DGRAM)
		goto out;

	old_state = sk->sk_state;
	if (!((1 << old_state) & (TCPF_CLOSE | NDF_LISTEN)))
		goto out;

	WRITE_ONCE(sk->sk_max_ack_backlog, backlog);
	/* Really, if the socket is already in listen state
	 * we can only allow the backlog to be adjusted.
	 */
	if (old_state != ND_LISTEN) {
		/* Enable TFO w/o requiring TCP_FASTOPEN socket option.
		 * Note that only TCP sockets (SOCK_STREAM) will reach here.
		 * Also fastopen backlog may already been set via the option
		 * because the socket was in TCP_LISTEN state previously but
		 * was shutdown() rather than close().
		 */
		// tcp_fastopen = sock_net(sk)->ipv4.sysctl_tcp_fastopen;
		// if ((tcp_fastopen & TFO_SERVER_WO_SOCKOPT1) &&
		//     (tcp_fastopen & TFO_SERVER_ENABLE) &&
		//     !inet_csk(sk)->icsk_accept_queue.fastopenq.max_qlen) {
		// 	fastopen_queue_tune(sk, backlog);
		// 	tcp_fastopen_init_key_once(sock_net(sk));
		// }
		err = nd_listen_start(sk, backlog);
		if (err)
			goto out;
		// tcp_call_bpf(sk, BPF_SOCK_OPS_TCP_LISTEN_CB, 0, NULL);
	}
	err = 0;

out:
	release_sock(sk);
	return err;
}
EXPORT_SYMBOL(nd_listen);


/*
 * Wait for an incoming connection, avoid race conditions. This must be called
 * with the socket locked.
 */
static int nd_sk_wait_for_connect(struct sock *sk, long timeo)
{
	struct nd_sock *dsk = nd_sk(sk);
	DEFINE_WAIT(wait);
	int err;

	/*
	 * True wake-one mechanism for incoming connections: only
	 * one process gets woken up, not the 'whole herd'.
	 * Since we do not 'race & poll' for established sockets
	 * anymore, the common case will execute the loop only once.
	 *
	 * Subtle issue: "add_wait_queue_exclusive()" will be added
	 * after any current non-exclusive waiters, and we know that
	 * it will always _stay_ after any new non-exclusive waiters
	 * because all non-exclusive waiters are added at the
	 * beginning of the wait-queue. As such, it's ok to "drop"
	 * our exclusiveness temporarily when we get woken up without
	 * having to remove and re-insert us on the wait queue.
	 */
	for (;;) {
		prepare_to_wait_exclusive(sk_sleep(sk), &wait,
					  TASK_INTERRUPTIBLE);
		release_sock(sk);
		if (reqsk_queue_empty(&dsk->icsk_accept_queue))
			timeo = schedule_timeout(timeo);
		sched_annotate_sleep();
		lock_sock(sk);
		err = 0;
		if (!reqsk_queue_empty(&dsk->icsk_accept_queue))
			break;
		err = -EINVAL;
		if (sk->sk_state != ND_LISTEN)
			break;
		err = sock_intr_errno(timeo);
		if (signal_pending(current))
			break;
		err = -EAGAIN;
		if (!timeo)
			break;
	}
	finish_wait(sk_sleep(sk), &wait);
	return err;
}

/*
 * This will accept the next outstanding connection.
 */
struct sock *nd_sk_accept(struct sock *sk, int flags, int *err, bool kern)
{
	struct nd_sock *dsk = nd_sk(sk);
	struct request_sock_queue *queue = &dsk->icsk_accept_queue;
	struct request_sock *req;
	struct sock *newsk;
	int error;

	lock_sock(sk);

	/* We need to make sure that this socket is listening,
	 * and that it has something pending.
	 */
	error = -EINVAL;
	if (sk->sk_state != ND_LISTEN)
		goto out_err;

	/* Find already established connection */
	if (reqsk_queue_empty(queue)) {
		long timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);

		/* If this is a non blocking socket don't sleep */
		error = -EAGAIN;
		if (!timeo)
			goto out_err;

		error = nd_sk_wait_for_connect(sk, timeo);
		if (error)
			goto out_err;
	}
	req = reqsk_queue_remove(queue, sk);
	newsk = req->sk;
	// printk("accept core id:%d\n", raw_smp_processor_id());
	// nd_rps_record_flow(newsk);

	// printk("src port:%d\n", inet_sk(newsk)->inet_num);
	// printk("src address:%d\n", inet_sk(newsk)->inet_saddr);

	// printk("dst address:%d\n", inet_sk(newsk)->inet_daddr);
	// printk("dst port:%d\n", ntohs(inet_sk(newsk)->inet_dport));
out:
	release_sock(sk);
	if (req){
		reqsk_put(req);
	}
	return newsk;
out_err:
	release_sock(sk);
	newsk = NULL;
	req = NULL;
	*err = error;
	goto out;
}
EXPORT_SYMBOL(nd_sk_accept);

/* return true if req was found in the ehash table */
// static bool reqsk_queue_unlink(struct request_sock *req)
// {
// 	struct inet_hashinfo *hashinfo = req_to_sk(req)->sk_prot->h.hashinfo;
// 	bool found = false;

// 	if (sk_hashed(req_to_sk(req))) {
// 		spinlock_t *lock = inet_ehash_lockp(hashinfo, req->rsk_hash);

// 		spin_lock(lock);
// 		found = __sk_nulls_del_node_init_rcu(req_to_sk(req));
// 		spin_unlock(lock);
// 	}
// 	// if (timer_pending(&req->rsk_timer) && del_timer_sync(&req->rsk_timer))
// 	// 	reqsk_put(req);
// 	return found;
// }

// void nd_sk_reqsk_queue_drop(struct sock *sk, struct request_sock *req)
// {
// 	if (reqsk_queue_unlink(req)) {
// 		reqsk_queue_removed(&nd_sk(sk)->icsk_accept_queue, req);
// 		reqsk_put(req);
// 	}
// }
// EXPORT_SYMBOL(nd_sk_reqsk_queue_drop);


struct request_sock *nd_reqsk_alloc(const struct request_sock_ops *ops,
				      struct sock *sk_listener,
				      bool attach_listener)
{
	struct request_sock *req = reqsk_alloc(ops, sk_listener,
					       attach_listener);

	if (req) {
		struct inet_request_sock *ireq = inet_rsk(req);
		atomic64_set(&ireq->ir_cookie, 0);
		// ireq->ireq_state = TCP_NEW_SYN_RECV;
		write_pnet(&ireq->ireq_net, sock_net(sk_listener));
		ireq->ireq_family = sk_listener->sk_family;
	}

	return req;
}
EXPORT_SYMBOL(nd_reqsk_alloc);

/* This function allows to force a closure of a socket after the call to
 * nd_create_openreq_child().
 */
void nd_sk_prepare_forced_close(struct sock *sk)
	__releases(&sk->sk_lock.slock)
{
	/* sk_clone_lock locked the socket and set refcnt to 2 */
	bh_unlock_sock(sk);
	sock_put(sk);

	/* The below has to be done to allow calling inet_csk_destroy_sock */
	sock_set_flag(sk, SOCK_DEAD);
	// percpu_counter_inc(sk->sk_prot->orphan_count);
	inet_sk(sk)->inet_num = 0;
}
EXPORT_SYMBOL(nd_sk_prepare_forced_close);

struct sock *nd_sk_reqsk_queue_add(struct sock *sk,
				      struct request_sock *req,
				      struct sock *child)
{
	struct request_sock_queue *queue = &nd_sk(sk)->icsk_accept_queue;

	spin_lock(&queue->rskq_lock);
	if (unlikely(sk->sk_state != ND_LISTEN)) {
		// inet_child_forget(sk, req, child);
		WARN_ON(sk->sk_state != TCP_CLOSE);
		WARN_ON(!sock_flag(sk, SOCK_DEAD));

		/* It cannot be in hash table! */
		WARN_ON(!sk_unhashed(sk));
		/* If it has not 0 inet_sk(sk)->inet_num, it must be bound */
		WARN_ON(inet_sk(sk)->inet_num && !inet_csk(sk)->icsk_bind_hash);
		/* Remove from the bind table */
		nd_put_port(child);
		/* Remove step may change latter */
		nd_sk_prepare_forced_close(child);
		sock_put(child);
		child = NULL;
	} else {
		req->sk = child;
		req->dl_next = NULL;
		if (queue->rskq_accept_head == NULL)
			WRITE_ONCE(queue->rskq_accept_head, req);
		else
			queue->rskq_accept_tail->dl_next = req;
		queue->rskq_accept_tail = req;
		sk_acceptq_added(sk);
	}
	spin_unlock(&queue->rskq_lock);
	return child;
}
EXPORT_SYMBOL(nd_sk_reqsk_queue_add);

static void nd_v4_init_req(struct request_sock *req,
                            const struct sock *sk_listener,
                            struct sk_buff *skb)
{
	    struct inet_request_sock *ireq = inet_rsk(req);
        // struct net *net = sock_net(sk_listener);

        sk_rcv_saddr_set(req_to_sk(req), ip_hdr(skb)->daddr);
        sk_daddr_set(req_to_sk(req), ip_hdr(skb)->saddr);
        ireq->ir_rmt_port = nd_hdr(skb)->source;
        ireq->ir_num = ntohs(nd_hdr(skb)->dest);
        ireq->ir_mark = inet_request_mark(sk_listener, skb);
		ireq->no_srccheck = inet_sk(sk_listener)->transparent;
		/* Note: tcp_v6_init_req() might override ir_iif for link locals */
		ireq->ir_iif = inet_request_bound_dev_if(sk_listener, skb);
        // RCU_INIT_POINTER(ireq->ireq_opt, nd_v4_save_options(net, skb));
		refcount_set(&req->rsk_refcnt, 1);
}


/**
 *	nd_sk_clone_lock - clone an inet socket, and lock its clone
 *	@sk: the socket to clone
 *	@req: request_sock
 *	@priority: for allocation (%GFP_KERNEL, %GFP_ATOMIC, etc)
 *
 *	Caller must unlock socket even in error path (bh_unlock_sock(newsk))
 */
struct sock *nd_sk_clone_lock(const struct sock *sk,
				 const struct request_sock *req,
				 const gfp_t priority)
{
	struct sock *newsk = sk_clone_lock(sk, priority);

	if (newsk) {
		struct nd_sock *dsk = nd_sk(newsk);

		dsk->icsk_bind_hash = NULL;

		inet_sk(newsk)->inet_dport = inet_rsk(req)->ir_rmt_port;
		inet_sk(newsk)->inet_num = inet_rsk(req)->ir_num;
		inet_sk(newsk)->inet_sport = htons(inet_rsk(req)->ir_num);

		/* listeners have SOCK_RCU_FREE, not the children */
		sock_reset_flag(newsk, SOCK_RCU_FREE);

		inet_sk(newsk)->mc_list = NULL;

		newsk->sk_mark = inet_rsk(req)->ir_mark;
		/* Deinitialize accept_queue to trap illegal accesses. */
		memset(&dsk->icsk_accept_queue, 0, sizeof(dsk->icsk_accept_queue));

	}
	return newsk;
}
EXPORT_SYMBOL_GPL(nd_sk_clone_lock);


/* This is not only more efficient than what we used to do, it eliminates
 * a lot of code duplication between IPv4/IPv6 SYN recv processing. -DaveM
 *
 * Actually, we could lots of memory writes here. tp of listening
 * socket contains all necessary default parameters.
 */
struct sock *nd_create_openreq_child(const struct sock *sk,
				      struct request_sock *req,
				      struct sk_buff *skb)
{
	struct sock *newsk = nd_sk_clone_lock(sk, req, GFP_ATOMIC);

	// const struct inet_request_sock *ireq = inet_rsk(req);
	// struct nd_sock *olddp, *newdp;
	// u32 seq;
	if (!newsk)
		return NULL;
	/*TODO: initialize the nd socket here */
	return newsk;
}
EXPORT_SYMBOL(nd_create_openreq_child);


struct dst_entry *nd_sk_route_child_sock(const struct sock *sk,
					    struct sock *newsk,
					    const struct request_sock *req)
{
	const struct inet_request_sock *ireq = inet_rsk(req);
	struct net *net = read_pnet(&ireq->ireq_net);
	struct inet_sock *newinet = inet_sk(newsk);
	struct ip_options_rcu *opt;
	struct flowi4 *fl4;
	struct rtable *rt;

	opt = rcu_dereference(ireq->ireq_opt);
	fl4 = &newinet->cork.fl.u.ip4;

	flowi4_init_output(fl4, ireq->ir_iif, ireq->ir_mark,
			   RT_CONN_FLAGS(sk), RT_SCOPE_UNIVERSE,
			   sk->sk_protocol, inet_sk_flowi_flags(sk),
			   (opt && opt->opt.srr) ? opt->opt.faddr : ireq->ir_rmt_addr,
			   ireq->ir_loc_addr, ireq->ir_rmt_port,
			   htons(ireq->ir_num), sk->sk_uid);

	security_req_classify_flow(req, flowi4_to_flowi(fl4));
	rt = ip_route_output_flow(net, fl4, sk);

	if (IS_ERR(rt))
		goto no_route;
	if (opt && opt->opt.is_strictroute && rt->rt_uses_gateway)
		goto route_err;
	return &rt->dst;

route_err:
	ip_rt_put(rt);
no_route:
	__IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);
	return NULL;
}
EXPORT_SYMBOL_GPL(nd_sk_route_child_sock);

void inet_sk_rx_dst_set(struct sock *sk, const struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);

	if (dst && dst_hold_safe(dst)) {
		sk->sk_rx_dst = dst;
		inet_sk(sk)->rx_dst_ifindex = skb->skb_iif;
	}
}

/*
 * Receive flow sync pkt: create new socket and push this to the accept queue
 */
struct sock *nd_create_con_sock(struct sock *sk, struct sk_buff *skb,
				  struct request_sock *req,
				  struct dst_entry *dst)
{
	struct inet_request_sock *ireq;
	struct inet_sock *newinet;
	struct nd_sock *newdp;
	struct sock *newsk;
	struct nd_sock *dsk;
	struct ip_options_rcu *inet_opt;
	// struct ndhdr *fhdr = nd_hdr(skb);
	if (sk_acceptq_is_full(sk))
		goto exit_overflow;

	newsk = nd_create_openreq_child(sk, req, skb);

	/* this init function may be used later */
	nd_init_sock(newsk);
	if (!newsk)
		goto exit_nonewsk;
 	if(!dst) {
 		dst = nd_sk_route_child_sock(sk, newsk, req);
	    if (!dst)
	        goto put_and_exit;
 	}

	newsk->sk_gso_type = SKB_GSO_TCPV4;
	inet_sk_rx_dst_set(newsk, skb);

	newdp		      = nd_sk(newsk);
	newinet		      = inet_sk(newsk);
	ireq		      = inet_rsk(req);
	sk_daddr_set(newsk, ireq->ir_rmt_addr);
	sk_rcv_saddr_set(newsk, ireq->ir_loc_addr);
	newsk->sk_bound_dev_if = ireq->ir_iif;
	newinet->inet_saddr   = ireq->ir_loc_addr;
	inet_opt	      = rcu_dereference(ireq->ireq_opt);
	RCU_INIT_POINTER(newinet->inet_opt, inet_opt);

	/* set up flow ID and flow size */
	dsk = nd_sk(newsk);
	// dsk->flow_id = fhdr->flow_id;
	dsk->core_id = nd_sk(sk)->core_id;
	// dsk->total_length = 1000000000;
	set_max_grant_batch(dst, dsk);
	/* set up max gso segment */
	sk_setup_caps(newsk, dst);

	/* add new socket to binding table */
	if (__nd_inherit_port(sk, newsk) < 0)
		goto put_and_exit;

	/* add socket to request queue */
    newsk = nd_sk_reqsk_queue_add(sk, req, newsk);
    if(newsk) {
		/* Unlike TCP, req_sock will not be inserted in the ehash table initially.*/

	    nd_set_state(newsk, ND_ESTABLISH);
		nd_ehash_nolisten(newsk, NULL);
    	// sock_rps_save_rxhash(newsk, skb);
    } 
	return newsk;

exit_overflow:

	NET_INC_STATS(sock_net(sk), LINUX_MIB_LISTENOVERFLOWS);
exit_nonewsk:

	dst_release(dst);
exit:
	// tcp_listendrop(sk);
	return NULL;
put_and_exit:
	// newinet->inet_opt = NULL;
	nd_sk_prepare_forced_close(newsk);
	sock_put(newsk);
	// inet_csk_prepare_forced_close(newsk);
	// tcp_done(newsk);
	// nd_set_state(newsk, TCP_CLOSE);
	goto exit;
}
EXPORT_SYMBOL(nd_create_con_sock);

struct sock* nd_conn_request(struct sock *sk, struct sk_buff *skb)
{
	// struct tcp_fastopen_cookie foc = { .len = -1 };
	// __u32 isn = TCP_SKB_CB(skb)->tcp_tw_isn;
	// struct tcp_options_received tmp_opt;
	// struct nd_sock *dp = nd_sk(sk);
	// struct net *net = sock_net(sk);
	struct sock *child = NULL;
	// struct dst_entry *dst = NULL;
	struct request_sock *req;
	// struct flowi fl;

	/* sk_acceptq_is_full(sk) should be
	 * the same as nd_sk_reqsk_is_full in ND.
	 */
	if (sk_acceptq_is_full(sk)) {
		goto drop;
	}

	/* create the request sock and don't attach to the listener socket. */
	req = nd_reqsk_alloc(&nd_request_sock_ops, sk, false);
	if (!req)
		goto drop;

	/* Initialize the request sock `*/
	nd_v4_init_req(req, sk, skb);

	if (security_inet_conn_request(sk, skb, req))
		goto drop_and_free;

	// reqsk_put(req);

    child = nd_create_con_sock(sk, skb, req, NULL);

    if (!child){
    	goto drop_and_free;
    }
	sk->sk_data_ready(sk);
	bh_unlock_sock(child);
	sock_put(child);
	return child;

drop_and_free:
	reqsk_free(req);

drop:
	return NULL;
}
EXPORT_SYMBOL(nd_conn_request);


