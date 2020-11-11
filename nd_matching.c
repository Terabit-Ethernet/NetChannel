#include "nd_impl.h"

// static void recevier_iter_event_handler(struct work_struct *work);
// static void sender_iter_event_handler(struct work_struct *work);
// __u64 js, je;
void nd_match_entry_init(struct nd_match_entry* entry, __be32 addr, 
 bool(*comp)(const struct list_head*, const struct list_head*)) {
	spin_lock_init(&entry->lock);
	nd_pq_init(&entry->pq, comp);
	INIT_HLIST_NODE(&entry->hash_link);
	INIT_LIST_HEAD(&entry->list_link);
	// struct nd_peer *peer;
	entry->dst_addr = addr;
}

void nd_mattab_init(struct nd_match_tab *table,
	bool(*comp)(const struct list_head*, const struct list_head*)) {
	int i;
	// int ret, opt;
	// struct nd_peer *peer;
	// struct inet_sock *inet;
	spin_lock_init(&table->lock);
	INIT_LIST_HEAD(&table->hash_list);

	table->comp = comp;
	printk("size of match entry: %lu\n", sizeof(struct nd_match_entry));
	table->buckets = kmalloc(sizeof(struct nd_match_slot) * ND_MATCH_BUCKETS, GFP_KERNEL);
	for (i = 0; i < ND_MATCH_BUCKETS; i++) {
		spin_lock_init(&table->buckets[i].lock);
		INIT_HLIST_HEAD(&table->buckets[i].head);
		table->buckets[i].count = 0;
	}
	// inet = inet_sk(table->sock->sk);
	// peer =  nd_peer_find(&nd_peers_table, 167772169, inet);
	// nd_xmit_control(construct_rts_pkt(table->sock->sk, 1, 2, 3), peer, table->sock->sk, 3000);

	return;
}

void nd_mattab_destroy(struct nd_match_tab *table) {
	int i = 0, j = 0;
	struct nd_match_slot *bucket = NULL;
	struct nd_match_entry *entry;
	struct hlist_node *n;
	printk("start to remove match table\n");
	for (i = 0; i < ND_MATCH_BUCKETS; i++) {
		bucket = &table->buckets[i];
		spin_lock_bh(&bucket->lock);
		for (j = 0; j < bucket->count; j++) {
			hlist_for_each_entry_safe(entry, n, &bucket->head, hash_link) {
				printk("kfree an entry\n");

				kfree(entry);
			}
		}
		spin_unlock_bh(&bucket->lock);
	}
	printk("finish remove match table\n");

	// sock_release(table->sock);
	kfree(table->buckets);
	return;
}

// lock order: bucket_lock > other two locks
void nd_mattab_add_new_sock(struct nd_match_tab *table, struct sock* sk) {
	struct nd_sock *dsk = nd_sk(sk);
	struct inet_sock *inet = inet_sk(sk); 
	struct nd_match_slot *bucket = nd_match_bucket(table, inet->inet_daddr);
	struct nd_match_entry *match_entry = NULL;
	spin_lock_bh(&bucket->lock);
	hlist_for_each_entry(match_entry, &bucket->head,
			hash_link) {
		if (match_entry->dst_addr == inet->inet_daddr) {
			spin_lock(&match_entry->lock);
			nd_pq_push(&match_entry->pq, &dsk->match_link);
			spin_unlock(&match_entry->lock);
			spin_unlock_bh(&bucket->lock);
			return;
		}
		// INC_METRIC(peer_hash_links, 1);
	}

	// create new match entry
	match_entry = kmalloc(sizeof(struct nd_match_entry), GFP_KERNEL);
	nd_match_entry_init(match_entry, inet->inet_daddr, table->comp);
	nd_pq_push(&match_entry->pq, &dsk->match_link);
	hlist_add_head(&match_entry->hash_link, &bucket->head);
	bucket->count += 1;
	// add this entry to the hash list
	spin_lock(&table->lock);
	list_add_tail(&match_entry->list_link, &table->hash_list);
	spin_unlock(&table->lock);

	spin_unlock_bh(&bucket->lock);
}

void nd_mattab_delete_sock(struct nd_match_tab *table, struct sock* sk) {
	struct nd_sock *dsk = nd_sk(sk);
	struct inet_sock *inet = inet_sk(sk); 
	struct nd_match_slot *bucket = nd_match_bucket(table, inet->inet_daddr);
	struct nd_match_entry *match_entry = NULL;
	// bool empty = false;
	spin_lock_bh(&bucket->lock);
	hlist_for_each_entry(match_entry, &bucket->head,
			hash_link) {
		if (match_entry->dst_addr == inet->inet_daddr) {
			break;
		}
		// INC_METRIC(peer_hash_links, 1);
	}
	if(match_entry != NULL) {
		spin_lock(&match_entry->lock);
		// assume the msg still in the list, which might not be true'
		nd_pq_delete(&match_entry->pq, &dsk->match_link);
		spin_unlock(&match_entry->lock);
	}

	spin_unlock_bh(&bucket->lock);

}

void nd_mattab_delete_match_entry(struct nd_match_tab *table, struct nd_match_entry* entry) {
	return;
}

void nd_epoch_init(struct nd_epoch *epoch) {
	int ret;
	// struct inet_sock *inet;
	// struct nd_peer* peer;
	epoch->epoch = 0;
	epoch->iter = 0;
	epoch->prompt = false;
	epoch->match_src_addr = 0;
	epoch->match_dst_addr = 0;
	INIT_LIST_HEAD(&epoch->rts_q);
	INIT_LIST_HEAD(&epoch->grants_q);
	epoch->grant_size = 0;
	epoch->rts_size = 0;
	epoch->min_rts = NULL;
	epoch->min_grant = NULL;
	// struct rte_timer epoch_timer;
	// struct rte_timer sender_iter_timers[10];
	// struct rte_timer receiver_iter_timers[10];
	// struct pim_timer_params pim_timer_params;
	epoch->start_cycle = 0;

	// current epoch and address
	epoch->cur_epoch = 0;
	epoch->cur_match_src_addr = 0;
	epoch->cur_match_dst_addr = 0;
	ret = sock_create(AF_INET, SOCK_DGRAM, IPPROTO_VIRTUAL_SOCK, &epoch->sock);
	// inet = inet_sk(epoch->sock->sk);
	// peer =  nd_peer_find(&nd_peers_table, 167772169, inet);

	if(ret) {
		printk("fail to create socket\n");
		return;
	}
	spin_lock_init(&epoch->lock);
	/* token xmit timer*/
	atomic_set(&epoch->remaining_tokens, 0);
	// atomic_set(&epoch->pending_flows, 0);

	hrtimer_init(&epoch->token_xmit_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED_SOFT);
	epoch->token_xmit_timer.function = &nd_token_xmit_event;

	// INIT_WORK(&epoch->token_xmit_struct, nd_xmit_token_handler);
	/* pHost Queue */
	nd_pq_init(&epoch->flow_q, flow_compare);


	epoch->wq = alloc_workqueue("epoch_wq",
			WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
	// INIT_WORK(&epoch->sender_iter_struct, sender_iter_event_handler);
	// INIT_WORK(&epoch->receiver_iter_struct, recevier_iter_event_handler);
	hrtimer_init(&epoch->epoch_timer, CLOCK_REALTIME, HRTIMER_MODE_ABS);
	hrtimer_init(&epoch->sender_iter_timer, CLOCK_REALTIME, HRTIMER_MODE_ABS);
	hrtimer_init(&epoch->receiver_iter_timer, CLOCK_REALTIME, HRTIMER_MODE_ABS);
	// hrtimer_start(&epoch->epoch_timer, ktime_set(0, 5000000), HRTIMER_MODE_ABS);
	// epoch->epoch_timer.function = &nd_new_epoch;
}

void nd_epoch_destroy(struct nd_epoch *epoch) {
	struct nd_rts *rts, *temp;
	struct nd_grant *grant, *temp2;
	struct socket *sk;
	hrtimer_cancel(&epoch->epoch_timer);
	hrtimer_cancel(&epoch->sender_iter_timer);
	hrtimer_cancel(&epoch->receiver_iter_timer);
	flush_workqueue(epoch->wq);
	destroy_workqueue(epoch->wq);
	spin_lock_bh(&epoch->lock);
	sk = epoch->sock;
	epoch->sock = NULL;
	list_for_each_entry_safe(rts, temp, &epoch->rts_q, list_link) {
		kfree(rts);
	}
	list_for_each_entry_safe(grant, temp2, &epoch->grants_q, list_link) {
		kfree(grant);
	}
	spin_unlock_bh(&epoch->lock);
	/* nd_destroy_sock needs to hold the epoch lock */
    sock_release(sk);

}
// void nd_send_all_rts (struct nd_match_tab *table, struct nd_epoch* epoch) {
// 	struct nd_match_entry *entry = NULL;
//  	// struct nd_peer *peer;
// 	// struct inet_sock *inet;
// 	// struct sk_buff* pkt;

// 	spin_lock(&table->lock);
// 	list_for_each_entry(entry, &table->hash_list, list_link) {
// 		struct list_head *list_head = NULL;
// 		struct nd_sock *dsk = NULL;
// 		spin_lock(&entry->lock);
// 		list_head = nd_pq_peek(&entry->pq);
// 		if(list_head != NULL) {
// 			// don't need to hold dsk lock, beacuase holding the priority lock
// 			dsk = list_entry(list_head, struct nd_sock, match_link);
// 			// send rts
// 			nd_xmit_control(construct_rts_pkt(epoch->sock->sk, 
// 				epoch->iter, epoch->epoch, dsk->total_length), 
// 				dsk->peer, epoch->sock->sk, nd_params.match_socket_port);
// 		}
// 		spin_unlock(&entry->lock);
// 	}
// 	// if(epoch->sock != NULL) {
// 	// 	inet = inet_sk(epoch->sock->sk);
// 	// 	// printk("inet is null: %d\n", inet == NULL);
// 	// 	peer =  nd_peer_find(&nd_peers_table, 167772169, inet);
// 	// 	pkt = construct_rts_pkt(epoch->sock->sk, epoch->iter, epoch->epoch, 3);
// 	// 	nd_xmit_control(pkt, peer, epoch->sock->sk, 3000);

// 	// }


// 	spin_unlock(&table->lock);

// }

// int nd_handle_rts (struct sk_buff *skb, struct nd_match_tab *table, struct nd_epoch *epoch) {
// 	struct nd_rts *rts;

// 	struct nd_rts_hdr *rh;
// 	struct iphdr *iph;
// 	if (!pskb_may_pull(skb, sizeof(struct nd_rts_hdr)))
// 		goto drop;		/* No space for header. */
// 	spin_lock_bh(&epoch->lock);
// 	if(epoch->sock == NULL) {
// 		spin_unlock_bh(&epoch->lock);
// 		goto drop;
// 	}
// 	rts = kmalloc(sizeof(struct nd_rts), GFP_KERNEL);
// 	INIT_LIST_HEAD(&rts->list_link);
// 	iph = ip_hdr(skb);
// 	rh = nd_rts_hdr(skb);
// 	rts->remaining_sz = rh->remaining_sz;

// 	// rts->epoch = rh->epoch; 
// 	// rts->iter = rh->iter;
// 	rts->peer = nd_peer_find(&nd_peers_table, iph->saddr, inet_sk(epoch->sock->sk));
// 	// spin_lock_bh(&epoch->lock);
// 	if (epoch->min_rts == NULL || epoch->min_rts->remaining_sz > rts->remaining_sz) {
// 		epoch->min_rts = rts;
// 	}
// 	list_add_tail(&rts->list_link, &epoch->rts_q);
// 	epoch->rts_size += 1;
// 	spin_unlock_bh(&epoch->lock);

// drop:
// 	kfree_skb(skb);
// 	return 0;
// }

// void nd_handle_all_rts(struct nd_match_tab* table, struct nd_epoch *epoch) {
// 	struct nd_rts *rts, *temp;
// 	// spin_lock_bh(&epoch->lock);
// 	uint32_t iter = READ_ONCE(epoch->iter);
// 	if(epoch->match_dst_addr == 0  && epoch->rts_size > 0) {
// 		if (nd_params.min_iter >= iter) {
// 			nd_xmit_control(construct_grant_pkt(epoch->sock->sk, 
// 				iter, epoch->epoch, epoch->min_rts->remaining_sz, epoch->cur_match_dst_addr == 0), 
// 				epoch->min_rts->peer, epoch->sock->sk, nd_params.match_socket_port);	
// 		} else {
// 			uint32_t index = 0;
// 			uint32_t i = 0;
// 			index = get_random_u32() % epoch->rts_size;
// 			list_for_each_entry(rts, &epoch->rts_q, list_link) {
// 				if (i == index) {
// 					nd_xmit_control(construct_grant_pkt(epoch->sock->sk, 
// 						iter, epoch->epoch, rts->remaining_sz, epoch->cur_match_dst_addr == 0), 
// 						rts->peer, epoch->sock->sk, nd_params.match_socket_port);
// 					break;
// 				}
// 				i += 1;
// 			}
// 		}
// 	}
// 	epoch->rts_size = 0;
// 	epoch->min_rts = NULL;
// 	list_for_each_entry_safe(rts, temp, &epoch->rts_q, list_link) {
// 		kfree(rts);
// 	}
// 	INIT_LIST_HEAD(&epoch->rts_q);
// 	// spin_unlock_bh(&epoch->lock);
// }


// int nd_handle_grant(struct sk_buff *skb, struct nd_match_tab *table, struct nd_epoch *epoch) {
// 	struct nd_grant *grant;

// 	struct nd_grant_hdr *gh;
// 	struct iphdr *iph;
// 	if (!pskb_may_pull(skb, sizeof(struct nd_grant_hdr)))
// 		goto drop;		/* No space for header. */
// 	spin_lock_bh(&epoch->lock);
// 	if(epoch->sock == NULL) {
// 		spin_unlock_bh(&epoch->lock);
// 		goto drop;
// 	}
// 	grant = kmalloc(sizeof(struct nd_grant), GFP_KERNEL);
// 	INIT_LIST_HEAD(&grant->list_link);
// 	iph = ip_hdr(skb);
// 	gh = nd_grant_hdr(skb);

// 	grant->remaining_sz = gh->remaining_sz;
// 	// grant->epoch = gh->epoch; 
// 	// grant->iter = gh->iter;
// 	grant->prompt = gh->prompt;
// 	grant->peer = nd_peer_find(&nd_peers_table, iph->saddr, inet_sk(epoch->sock->sk));
// 	if (epoch->min_grant == NULL || epoch->min_grant->remaining_sz > grant->remaining_sz) {
// 		epoch->min_grant = grant;
// 	}
// 	list_add_tail(&grant->list_link, &epoch->grants_q);
// 	epoch->grant_size += 1;
// 	spin_unlock_bh(&epoch->lock);

// drop:
// 	kfree_skb(skb);

// 	return 0;
// }

// void nd_handle_all_grants(struct nd_match_tab *table, struct nd_epoch *epoch) {
// 	struct nd_grant *grant, *temp, *resp = NULL;
// 	// spin_lock_bh(&epoch->lock);
// 	uint32_t iter = READ_ONCE(epoch->iter);
// 	if(epoch->match_src_addr == 0 && epoch->grant_size > 0) {
// 		if (nd_params.min_iter >= iter) {
// 			// printk("send accept pkt:%d\n", __LINE__);
// 			nd_xmit_control(construct_accept_pkt(epoch->sock->sk, 
// 				iter, epoch->epoch), 
// 				epoch->min_grant->peer, epoch->sock->sk, nd_params.match_socket_port);
// 			resp = epoch->min_grant;
// 		} else {
// 			uint32_t index = 0;
// 			uint32_t i = 0;
// 			index = get_random_u32() % epoch->grant_size;
// 			list_for_each_entry(grant, &epoch->grants_q, list_link) {
// 				if (i == index) {
// 					// printk("send accept pkt:%d\n", __LINE__);
// 					nd_xmit_control(construct_accept_pkt(epoch->sock->sk, 
// 						iter, epoch->epoch), 
// 						grant->peer, epoch->sock->sk, nd_params.match_socket_port);
// 					resp = grant;
// 					break;
// 				}
// 				i += 1;
// 			}
// 		}
// 		epoch->match_src_addr = resp->peer->addr;
// 		if(resp != NULL && resp->prompt) {
// 			epoch->cur_match_src_addr = resp->peer->addr;
// 		}
// 	}

// 	epoch->grant_size = 0;
// 	epoch->min_grant = NULL;

// 	list_for_each_entry_safe(grant, temp, &epoch->grants_q, list_link) {
// 		kfree(grant);

// 	}
// 	INIT_LIST_HEAD(&epoch->grants_q);
// 	// spin_unlock_bh(&epoch->lock);
// }

// int nd_handle_accept(struct sk_buff *skb, struct nd_match_tab *table, struct nd_epoch *epoch) {
// 	struct nd_accept_hdr *ah;
// 	struct iphdr *iph;

// 	if (!pskb_may_pull(skb, sizeof(struct nd_accept_hdr)))
// 		goto drop;		/* No space for header. */
// 	iph = ip_hdr(skb);
// 	ah = nd_accept_hdr(skb);
// 	printk("receive accept pkt: %llu\n", ah->epoch);
// 	spin_lock_bh(&epoch->lock);
// 	if(epoch->match_dst_addr == 0)
// 		epoch->match_dst_addr = iph->saddr;
// 	spin_unlock_bh(&epoch->lock);

// drop:
// 	kfree_skb(skb);
// 	return 0;
// }

// static void recevier_iter_event_handler(struct work_struct *work) {
// 	struct nd_epoch *epoch = container_of(work, struct nd_epoch, receiver_iter_struct);
// 	uint32_t iter;
// 	spin_lock_bh(&epoch->lock);

// 	iter = READ_ONCE(epoch->iter);
// 	if(iter > 0) {
// 		nd_handle_all_grants(&nd_match_table, epoch);
// 	}
// 	// advance iteration
// 	iter += 1;
// 	WRITE_ONCE(epoch->iter, iter);
// 	if(iter > nd_params.num_iters) {
// 		epoch->cur_match_src_addr = epoch->match_src_addr;
// 		epoch->cur_match_dst_addr = epoch->match_dst_addr;
// 		epoch->cur_epoch = epoch->epoch;
// 		// nd_epoch->min_grant = NULL;
// 		// nd_epoch->grant_size = 0;
// 		// list_for_each_entry_safe(grant, temp, &epoch->grants_q, list_link) {
// 		// 	kfree(grant);
// 		// }
// 		spin_unlock_bh(&epoch->lock);
// 		return;
// 	} 
// 	nd_send_all_rts(&nd_match_table, epoch);
// 	spin_unlock_bh(&epoch->lock);
// }

/* Token */
enum hrtimer_restart nd_token_xmit_event(struct hrtimer *timer) {
	// struct nd_grant* grant, temp;
	struct nd_epoch *epoch = container_of(timer, struct nd_epoch, token_xmit_timer);

	// printk("token timer handler is called 1\n");
	spin_lock(&epoch->lock);
	/* reset the remaining tokens to zero */
	// atomic_set(&epoch->remaining_tokens, 0);	
	nd_xmit_token(epoch);
	spin_unlock(&epoch->lock);

 	// queue_work(nd_epoch.wq, &nd_epoch.token_xmit_struct);
	return HRTIMER_NORESTART;

}
/* Assume hold socket lock 
 * Return 0 if flow should be pushed_back;
 * Return 1 if RMEM is unavailable.
 * Return 2 if timer is setup.
 */

int rtx_bytes_count(struct nd_sock* dsk, __u32 prev_grant_nxt) {
	int retransmit_bytes = 0; 
	if(dsk->receiver.rcv_nxt < prev_grant_nxt) {
		int i = 0;
		__u32 sum = 0;
		// printk("prev_grant_nxt:%u\n", prev_grant_nxt);
		while(i < dsk->num_sacks) {
			__u32 start_seq = dsk->selective_acks[i].start_seq;
			__u32 end_seq = dsk->selective_acks[i].end_seq;
			// printk("start seq: %u\n", start_seq);
			// printk("end seq:%u\n", end_seq);
			if(start_seq > prev_grant_nxt)
				goto next;
			if(end_seq > prev_grant_nxt) {
				end_seq = prev_grant_nxt;
			}
			sum += end_seq - start_seq;
		next:
			i++;
		}
		retransmit_bytes = prev_grant_nxt - dsk->receiver.rcv_nxt - sum;
		// atomic_add_return(retransmit_bytes, &nd_epoch.remaining_tokens);
	} 
	return retransmit_bytes;
}

/* Assume BH is disabled and epoch->lock is hold
 * Return true if we need to push back the flow to pq.
 */
 // ktime_t start2,end2;
 // __u64 num_tokens = 0;
 // ktime_t total_time = 0;
void nd_xmit_token(struct nd_epoch *epoch) {
	struct list_head *match_link;
	struct sock *sk;
	struct nd_sock *dsk;
	struct inet_sock *inet;
		// start2 = ktime_get();
	// printk("nd xmit token\n");
	while(!nd_pq_empty(&epoch->flow_q)) {
		bool not_push_bk = false;
		if(atomic_read(&nd_epoch.remaining_tokens) >= nd_params.control_pkt_bdp / 2 
			&& atomic_read(&nd_epoch.remaining_tokens) != 0) {
			// WARN_ON(true);
			return;
		}
		match_link = nd_pq_peek(&epoch->flow_q);
		dsk =  list_entry(match_link, struct nd_sock, match_link);
		sk = (struct sock*)dsk;
		inet = inet_sk(sk);
		nd_pq_pop(&epoch->flow_q);
 		bh_lock_sock(sk);
 		if(sk->sk_state == ND_ESTABLISH) {
 			dsk->receiver.prev_grant_bytes = 0;
	 		if (!sock_owned_by_user(sk)) {
	 			int grant_bytes = calc_grant_bytes(sk);
	 			// printk("grant bytes:%d\n", grant_bytes);
	 			not_push_bk = xmit_batch_token(sk, grant_bytes, true);
		 		if(grant_bytes == dsk->receiver.max_grant_batch) {
					dsk->prev_grant_nxt = dsk->grant_nxt;
					dsk->grant_nxt = dsk->new_grant_nxt;
		  			if (!not_push_bk){
		  				nd_pq_push(&epoch->flow_q, &dsk->match_link);
		  			}
		 		}
		 		else {
	 				// xmit_batch_token(sk, grant_bytes, true);
					// atomic_add(dsk->receiver.grant_batch, &nd_epoch.remaining_tokens);
					// printk("set timer deferred 1\n");
	 				test_and_set_bit(ND_TOKEN_TIMER_DEFERRED, &sk->sk_tsq_flags);
		 		}

	 		// 	if (grant_bytes < dsk->receiver.grant_batch) {
				// 	printk("RMEM_LIMIT\n");
			 //    	test_and_set_bit(ND_RMEM_CHECK_DEFERRED, &sk->sk_tsq_flags);
			 //    	goto unlock;
				// } else {
					
				// }
	 		} else {
	 			// printk("delay \n");
	 			int grant_bytes = calc_grant_bytes(sk);
	 			if (!grant_bytes)
	 				 xmit_batch_token(sk, grant_bytes, false);
	 			// printk("delay bytes:%d\n", grant_bytes);
	 			// atomic_add(dsk->receiver.grant_batch, &epoch->remaining_tokens);
	 			// atomic_add(dsk=>receiver.);
	 			/* pre-assign the largest number of tokens; will be deleted later */
				// atomic_add(dsk->receiver.grant_batch, &nd_epoch.remaining_tokens);
				// printk("set timer deferred\n");
	 			test_and_set_bit(ND_TOKEN_TIMER_DEFERRED, &sk->sk_tsq_flags);
	 		}
 		} else {
 			goto unlock;
 		}

		bh_unlock_sock(sk);
		break;
unlock:
        bh_unlock_sock(sk);
	}
	if (!nd_pq_empty(&epoch->flow_q)) {
		// printk("timer expire time:%d\n", nd_params.rtt * 10 * 1000);
		// hrtimer_start(&nd_epoch.token_xmit_timer, ktime_set(0, nd_params.rtt * 10 * 1000), HRTIMER_MODE_REL);
		// nd_epoch.token_xmit_timer.function = &nd_token_xmit_event;
	}
	// end2 = ktime_get();
	// total_time = ktime_add(total_time, ktime_sub(end2, start2));
	// num_tokens += 1;
	// if(num_tokens == 1000) {
	// 	num_tokens = 0;
	// 	printk("transmission time:%llu\n", ktime_to_us(total_time) / 1000);
	// 	total_time = ktime_set(0, 0);
	// }
}

void nd_xmit_token_handler(struct work_struct *work) {
	// struct nd_epoch *epoch = container_of(work, struct nd_epoch, token_xmit_struct);
}



// static void sender_iter_event_handler(struct work_struct *work) {
// 	struct nd_epoch *epoch = container_of(work, struct nd_epoch, sender_iter_struct);
// 	uint32_t iter;
// 	// je = ktime_get_ns();

// 	spin_lock_bh(&epoch->lock);
// 	iter = READ_ONCE(epoch->iter);
//  	// if(nd_epoch.epoch % 100 == 0 && nd_epoch.iter == 1) {
//  	// 	printk("iter:%u time diff:%llu \n", iter, je - js);
//  	// }
// 	if(iter <= nd_params.num_iters) {
// 		nd_handle_all_rts(&nd_match_table, epoch);
// 	}
// 	spin_unlock_bh(&epoch->lock);
// }
// enum hrtimer_restart receiver_iter_event(struct hrtimer *timer) {
// 	// struct nd_grant* grant, temp;
//  	uint32_t iter;
//  	hrtimer_forward(timer, hrtimer_cb_get_time(timer), ktime_set(0, nd_params.iter_size));
//  	queue_work(nd_epoch.wq, &nd_epoch.receiver_iter_struct);
//  	iter = READ_ONCE(nd_epoch.iter);
//  	if(iter >= nd_params.num_iters) {
//  		return HRTIMER_NORESTART;
//  	}
// 	return HRTIMER_RESTART;

// }

// enum hrtimer_restart sender_iter_event(struct hrtimer *timer) {
//  	uint32_t iter;
//  	hrtimer_forward(timer,hrtimer_cb_get_time(timer),ktime_set(0, nd_params.iter_size));
//  	queue_work(nd_epoch.wq, &nd_epoch.sender_iter_struct);

//  	// js = ktime_get_ns();
//  	iter = READ_ONCE(nd_epoch.iter);

//  	if(iter >= nd_params.num_iters) {
//  		return HRTIMER_NORESTART;
//  	}
// 	return HRTIMER_RESTART;

// }

// enum hrtimer_restart nd_new_epoch(struct hrtimer *timer) {

//  	hrtimer_forward(timer,hrtimer_cb_get_time(timer),ktime_set(0,nd_params.epoch_size));
// 	nd_epoch.epoch += 1;
// 	WRITE_ONCE(nd_epoch.iter, 0);
// 	nd_epoch.match_src_addr = 0;
// 	nd_epoch.match_dst_addr = 0;
// 	nd_epoch.prompt = false;
// 	hrtimer_start(&nd_epoch.receiver_iter_timer, ktime_set(0, 0), HRTIMER_MODE_ABS);
// 	nd_epoch.receiver_iter_timer.function = &receiver_iter_event;
// 	hrtimer_start(&nd_epoch.sender_iter_timer, ktime_set(0, nd_params.iter_size / 2), HRTIMER_MODE_ABS);
// 	nd_epoch.sender_iter_timer.function = &sender_iter_event;

// 	return HRTIMER_RESTART;
// }
