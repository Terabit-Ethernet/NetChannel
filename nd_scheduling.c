#include "nd_impl.h"

#define MAX_ACTIVE_CORE 4

struct xmit_core_table xmit_core_tab;
struct rcv_core_table rcv_core_tab;

extern uint32_t backlog_rcv;

int calc_grant_bytes(struct sock *sk) {
	    struct nd_sock* dsk = nd_sk(sk);
	    int max_gso_data = (int)dsk->receiver.max_gso_data;
        int free_space = nd_space(sk);
        int allowed_space = nd_full_space(sk);
        int full_space = min_t(int, dsk->receiver.grant_batch, allowed_space);
        int grant_bytes = dsk->receiver.grant_batch;

        if (unlikely(max_gso_data > allowed_space)) {
            return 0;
        }
        if (dsk->receiver.prev_grant_bytes >= dsk->receiver.grant_batch)
        	return 0;
        if (free_space < dsk->receiver.grant_batch * 2) {
        	// printk("free space:%d\n", free_space);
        	// printk("max gso data:%d\n", max_gso_data);
                return 0;
        }
        if (grant_bytes > free_space)
        	grant_bytes = free_space;
        grant_bytes -= dsk->receiver.prev_grant_bytes;
        if (grant_bytes <= 0) {
        	// printk("prev grant bytes full grant bytes: 0\n");
        	return 0;
        }
		if(grant_bytes > dsk->receiver.max_gso_data)
        	grant_bytes = grant_bytes / dsk->receiver.max_gso_data * dsk->receiver.max_gso_data;
        return grant_bytes;
}

bool flow_compare(const struct list_head* node1, const struct list_head* node2) {
    struct nd_sock *e1, *e2;
    e1 = list_entry(node1, struct nd_sock, match_link);
    e2 = list_entry(node2, struct nd_sock, match_link);
    if(e1->total_length > e2->total_length)
        return true;
    if(ktime_compare(e1->start_time, e2->start_time) > 0)
    	return true;
    return false;

}

void rcv_core_entry_init(struct rcv_core_entry *entry, int core_id) {
	spin_lock_init(&entry->lock);
	/* token xmit timer*/
	atomic_set(&entry->remaining_tokens, 0);
	// atomic_set(&epoch->pending_flows, 0);
	entry->core_id = core_id;
	entry->state = ND_IDLE;
	hrtimer_init(&entry->flowlet_done_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED_SOFT);
	entry->flowlet_done_timer.function = &flowlet_done_event;

	/* pHost Queue */
	nd_pq_init(&entry->flow_q, flow_compare);

	INIT_LIST_HEAD(&entry->list_link);
	INIT_WORK(&entry->token_xmit_struct, nd_xmit_token_event);


}

int rcv_core_table_init(struct rcv_core_table *tab) {
	int i;
	// atomic_set(&tab->remaining_tokens, 0);
	tab->num_active_cores = 0;
	spin_lock_init(&tab->lock);
	INIT_LIST_HEAD(&tab->sche_list);
	tab->wq = alloc_workqueue("nd-rcv-wq",
		WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
	if(!tab->wq)
		return -ENOMEM;
	for (i = 0; i < NR_CPUS; i++) {
		rcv_core_entry_init(&tab->table[i], i);
	}
	return 0;
}

void rcv_core_table_destory(struct rcv_core_table *tab) {
	flush_workqueue(tab->wq);
	destroy_workqueue(tab->wq);
}

/* Assume table is hold */
void rcv_invoke_next(struct rcv_core_table* tab) {
	if (!list_empty(&tab->sche_list)) {
		struct rcv_core_entry *next_entry = list_first_entry(&tab->sche_list, struct rcv_core_entry, list_link);
		// WARN_ON(next_entry == entry);
		// WARN_ON(skb_queue_empty(next_entry->token_q));
		list_del_init(&next_entry->list_link);
		tab->num_active_cores += 1;
		// printk("invoke next CPU Core:%d\n", raw_smp_processor_id());
		/* need to check whether is from the same core or not */
		queue_work_on(next_entry->core_id, tab->wq, &next_entry->token_xmit_struct);
		// hrtimer_start(&next_entry->data_xmit_timer, ns_to_ktime(0), 
		// HRTIMER_MODE_REL_PINNED_SOFT);
	}
}

#define ND_RMEM_LIMIT 1
#define ND_TIMER_SETUP 2

int xmit_batch_token(struct sock *sk, int grant_bytes, bool handle_rtx) {
	struct nd_sock *dsk = nd_sk(sk);
	struct rcv_core_entry* entry = &rcv_core_tab.table[dsk->core_id];
	int grant_len = 0;
	struct inet_sock *inet;
	int push_bk = 0;
	int retransmit_bytes = 0;
	ktime_t tx_time = ktime_get();
	__u32 prev_grant_nxt = dsk->prev_grant_nxt;
	inet = inet_sk(sk);
	// dsk->new_grant_nxt = dsk->grant_nxt;
	// printk("process core id:%d\n", raw_smp_processor_id());
	// printk("entry core id:%d\n", entry->core_id);
	// printk("entry address:%p\n", entry);
	// printk("xmit token cpu:%d\n", dsk->core_id);
	if (dsk->receiver.flow_finish_wait) {
		// printk("flow wait\n");
		return ND_TIMER_SETUP;
	}
	/* this is only exception for retransmission*/
	if (grant_bytes < 0)
		grant_bytes = 0;
	/*compute total sack bytes*/
	if(handle_rtx && 
		/* rcv next must be smaller than previous round grant nxt */
		dsk->receiver.rcv_nxt < prev_grant_nxt && 
		/* rcv next should be less than current grant nxt - grant_batch */
		(dsk->receiver.rcv_nxt + dsk->receiver.grant_batch < dsk->grant_nxt 
			|| dsk->grant_nxt == dsk->total_length) &&
		/* don't to immediate retransmission */
		ktime_to_us(ktime_sub(tx_time, dsk->receiver.last_rtx_time)) > 50) {
		// printk("previous grant next:%u\n", prev_grant_nxt);
		dsk->receiver.last_rtx_time = ktime_get();
		retransmit_bytes = rtx_bytes_count(dsk, prev_grant_nxt);
		grant_len += retransmit_bytes;
		// atomic_add_return(retransmit_bytes, &nd_epoch.remaining_tokens);
		if (retransmit_bytes > nd_params.control_pkt_bdp / 2)
			grant_bytes = 0;
		// for debugging purpose now; should remove this later
		handle_rtx = false;
	} else {
		handle_rtx = false;
	}
	/* if retransmit_bytes is larger, then we don't increment grant_nxt */

	// printk("grant bytes:%u\n", grant_bytes);
	/* set grant next*/
	/* receiver buffer bottleneck; or token is dropped */
	// if(prev_grant_nxt == dsk->receiver.rcv_nxt) {
	// 	dsk->grant_nxt = dsk->receiver.rcv_nxt;
	// 	printk("shrink grant nxt:%d\n", dsk->grant_nxt);
	// }
	/* this is a temporary solution */
	if(dsk->new_grant_nxt + grant_bytes > dsk->total_length) {
		grant_bytes =  dsk->total_length - dsk->grant_nxt;
		dsk->new_grant_nxt = dsk->total_length;
	} else {
		dsk->new_grant_nxt += grant_bytes;
	}

	grant_len += grant_bytes;
	if (grant_len == 0) {
		dsk->receiver.rmem_exhausted += 1;
	}
	if(dsk->new_grant_nxt == dsk->total_length) {
		push_bk = ND_TIMER_SETUP;
		/* TO DO: setup a timer here */
		/* current set timer to be 10 RTT */
		dsk->receiver.flow_finish_wait = true;
		// printk("set up flow wait timer\n");
		hrtimer_start(&dsk->receiver.flow_wait_timer, ns_to_ktime(nd_params.rtt * 40 * 1000), 
			HRTIMER_MODE_REL_PINNED_SOFT);
	} else {
		// printk("setup flow wait timer\n");
		// printk("expire time:%d\n", nd_params.rtt * 10 * 1000);
		hrtimer_start(&dsk->receiver.flow_wait_timer, ns_to_ktime(nd_params.rtt * 40 * 1000), 
			HRTIMER_MODE_REL_PINNED_SOFT);
	}
	// printk("xmit token grant next:%u\n", dsk->new_grant_nxt);
	// printk("prev_grant_nxt:%u\n", dsk->prev_grant_nxt);
	// printk ("dsk->receiver.rcv_nxt:%u\n", dsk->receiver.rcv_nxt);
	// printk("grant_len:%d\n", grant_len);
	// atomic_add(grant_len, &entry->remaining_tokens);
	dsk->receiver.prev_grant_bytes += grant_len;
	// atomic_add(grant_len, &dsk->receiver.in_flight_bytes);
	// printk("send token");
	if(handle_rtx || grant_len != 0)
		nd_xmit_control(construct_token_pkt((struct sock*)dsk, 3, prev_grant_nxt, dsk->new_grant_nxt, handle_rtx),
	 	sk, inet->inet_dport);
	return push_bk;
}

/* assume entry lock is hold and bh is disabled */
bool nd_xmit_token_single_core(struct rcv_core_entry *entry) {
	bool find_flow = false;
	struct list_head *match_link;
	struct nd_sock *dsk;
	struct inet_sock *inet;
	struct sock* sk;

	while(!nd_pq_empty(&entry->flow_q)) {
		int not_push_bk = 0;
		bool handle_rtx = false;
		// printk("pq size:%d\n", nd_pq_size(&entry->flow_q));
		match_link = nd_pq_peek(&entry->flow_q);
		dsk =  list_entry(match_link, struct nd_sock, match_link);
		sk = (struct sock*)dsk;
		inet = inet_sk(sk);
		nd_pq_pop(&entry->flow_q);
 		bh_lock_sock(sk);
 		dsk->receiver.in_pq = false;
 		// printk("xmit token for socket:%d\n", ntohs(inet->inet_dport));
 		if(sk->sk_state == ND_ESTABLISH && !dsk->receiver.finished_at_receiver) {
			// int retransmit_bytes;
			// dsk->receiver.prev_grant_bytes = 0;
			// if(ntohs(inet->inet_dport) == 1000) {
				// printk("port:%d", ntohs(inet->inet_dport));
				// printk(" grant bytes:%d", grant_bytes);
				// printk(" space: %d\n", nd_space(sk));

			// }
			// retransmit_bytes = rtx_bytes_count(dsk, dsk->prev_grant_nxt);
	 		// if (!sock_owned_by_user(sk)
			//  ) {
	 		// 	handle_rtx = true;
	 		// 	// printk("sock_owned_by_user\n");
	 		// }
	 		// printk("dsk address:%p\n", dsk);
 			// printk("single core grant bytes:%d\n", grant_bytes);
 			// printk("retransmit byte:%d\n", retransmit_bytes);

 			/* need morer work on that */
			WARN_ON(dsk->receiver.grant_batch + dsk->grant_nxt >  dsk->total_length);
			atomic_add(dsk->receiver.grant_batch, &entry->remaining_tokens);
			atomic_add(dsk->receiver.grant_batch, &dsk->receiver.in_flight_bytes);
	 		if(!sock_owned_by_user(sk)) {
	 			int grant_bytes; 
				grant_bytes = calc_grant_bytes(sk);
 				not_push_bk = xmit_batch_token(sk, grant_bytes, handle_rtx);
	  			if (!dsk->receiver.flow_finish_wait && grant_bytes != 0){
	  				// printk("push back socket \n");
					/* reinitialize the state for the next time*/
					if(dsk->receiver.grant_batch != dsk->receiver.prev_grant_bytes) {
						atomic_sub(dsk->receiver.grant_batch - dsk->receiver.prev_grant_bytes, &entry->remaining_tokens);
						atomic_sub(dsk->receiver.grant_batch - dsk->receiver.prev_grant_bytes, &dsk->receiver.in_flight_bytes);
					}
					dsk->prev_grant_nxt = dsk->grant_nxt;
					dsk->grant_nxt = dsk->new_grant_nxt;
	  				nd_pq_push(&entry->flow_q, &dsk->match_link);
	  				dsk->receiver.in_pq = true;
					dsk->receiver.prev_grant_bytes = 0;
					dsk->receiver.grant_batch = min_t(uint32_t, dsk->total_length - dsk->grant_nxt,
		 				dsk->receiver.max_grant_batch);
	  			} 
	  			if (!dsk->receiver.flow_finish_wait && grant_bytes == 0) {
	  				test_and_set_bit(ND_TOKEN_TIMER_DEFERRED, &sk->sk_tsq_flags);
	  			}
  				// printk("reach here:%d\n", __LINE__);
	 		}
	 		else if(!test_bit(ND_TOKEN_TIMER_DEFERRED, &sk->sk_tsq_flags)) {
  				// printk("token timer deferred set\n");
 				test_and_set_bit(ND_TOKEN_TIMER_DEFERRED, &sk->sk_tsq_flags);
	 		}
 		} else {
 			goto unlock;
 		}
 		find_flow = true;
		bh_unlock_sock(sk);
		break;
unlock:
        bh_unlock_sock(sk);
	}
	if (!nd_pq_empty(&entry->flow_q)) {
	}
	return find_flow;
}

/* Assume local bh is disabled */
void nd_update_and_schedule_sock(struct nd_sock *dsk) {
	struct rcv_core_entry *entry = &rcv_core_tab.table[dsk->core_id];
	WARN_ON(dsk->receiver.in_pq);
	spin_lock(&entry->lock);
	/* clean unsent token */
	if(dsk->receiver.grant_batch != dsk->receiver.prev_grant_bytes) {
		atomic_sub(dsk->receiver.grant_batch - dsk->receiver.prev_grant_bytes, &entry->remaining_tokens);
		atomic_sub(dsk->receiver.grant_batch - dsk->receiver.prev_grant_bytes, &dsk->receiver.in_flight_bytes);
	}
	dsk->prev_grant_nxt = dsk->grant_nxt;
	dsk->grant_nxt = dsk->new_grant_nxt;
	dsk->receiver.prev_grant_bytes = 0;
	dsk->receiver.grant_batch = min_t(uint32_t, dsk->total_length - dsk->grant_nxt,
		 dsk->receiver.max_grant_batch);
	if(!dsk->receiver.in_pq) {
		nd_pq_push(&entry->flow_q, &dsk->match_link);
		dsk->receiver.in_pq = true;
	}
	spin_unlock(&entry->lock);
}

/* Assume local bh is disabled */
void nd_unschedule_sock(struct nd_sock *dsk) {
	struct rcv_core_entry *entry = &rcv_core_tab.table[dsk->core_id];
	// WARN_ON(!dsk->receiver.in_pq);
	spin_lock(&entry->lock);
	if(dsk->receiver.in_pq) {
		nd_pq_delete(&entry->flow_q, &dsk->match_link);
		dsk->receiver.in_pq = false;
	}
	spin_unlock(&entry->lock);
}

/* Process Context */
void nd_xmit_token_event(struct work_struct *w) {
	struct rcv_core_entry *entry = container_of(w, struct rcv_core_entry, token_xmit_struct);
	bool find_flow = false;
		// start2 = ktime_get();
	// printk("nd xmit token\n");
	spin_lock_bh(&entry->lock);
	// WARN_ON(entry->is_active);
	WARN_ON(entry->state != ND_IN_QUEUE);
	if(entry->state == ND_ACTIVE) {
		// WARN_ON(true);
		goto not_find_flow;
	}
	entry->state = ND_ACTIVE;
	// printk("reach here:%d\n", __LINE__);
	find_flow = nd_xmit_token_single_core(entry);
	if(!find_flow)
		entry->state = ND_IDLE;

	/* not enough pkt is granted */
	if(atomic_read(&entry->remaining_tokens) <= nd_params.control_pkt_bdp / 2) {
		entry->state = ND_IDLE;
		find_flow = false;
	}

not_find_flow:
	spin_unlock_bh(&entry->lock);
	if(!find_flow) {
		spin_lock_bh(&rcv_core_tab.lock);
		rcv_core_tab.num_active_cores -= 1;
		rcv_invoke_next(&rcv_core_tab);
		spin_unlock_bh(&rcv_core_tab.lock);
	}
}

void rcv_handle_new_flow(struct nd_sock* dsk) {
	int core_id = dsk->core_id;
	// bool is_empty = false;
	struct rcv_core_entry* entry = &rcv_core_tab.table[core_id];
	WARN_ON(!in_softirq());
	spin_lock(&entry->lock);

	/* push the long flow to the control plane for scheduling*/
	nd_pq_push(&entry->flow_q, &dsk->match_link);
	dsk->receiver.in_pq = true;
	dsk->receiver.prev_grant_bytes = 0;
	dsk->receiver.grant_batch = min_t(uint32_t, dsk->total_length - dsk->grant_nxt,
		dsk->receiver.max_grant_batch);
	// printk("dsk->address:%p\n", dsk);
	// printk("dsk->match_link:%p\n", &dsk->match_link);
	// printk("pq peek:%p\n", nd_pq_peek(&entry->flow_q));
	// printk("pq size:%d\n", nd_pq_size(&entry->flow_q));
	// printk("handle new flow flow wait:%d\n", dsk->receiver.flow_wait);
	// if(nd_pq_size(&entry->flow_q) == 1) {
	// 	is_empty = true;
	// }
	// printk("handle new flow core id:%d\n", core_id);
	// printk("entry state:%d\n", entry->state);f
	// printk("handle new flow\n");
	if(entry->state == ND_IDLE) {
		spin_lock(&rcv_core_tab.lock);
		// printk("entry state:%d\n", entry->state);

		/* list empty*/
		if(rcv_core_tab.num_active_cores < MAX_ACTIVE_CORE) {
			rcv_core_tab.num_active_cores += 1;
			entry->state = ND_ACTIVE;
			// printk("reach here:%d\n", __LINE__);
			spin_unlock(&rcv_core_tab.lock);
			// printk("reach here:%d\n", __LINE__);
			nd_xmit_token_single_core(entry);
			goto end;
		} else {
			entry->state = ND_IN_QUEUE;
			list_add_tail(&entry->list_link, &rcv_core_tab.sche_list);
		}
		spin_unlock(&rcv_core_tab.lock);
	}
end:
	spin_unlock(&entry->lock);
}

/* entry lock is hold and bh is disabled */
void rcv_flowlet_done(struct rcv_core_entry *entry) {

	bool pq_empty = nd_pq_empty(&entry->flow_q);
	if(atomic_read(&entry->remaining_tokens) <= nd_params.control_pkt_bdp / 2 
		&& entry->state == ND_ACTIVE) {
		spin_lock(&rcv_core_tab.lock);
		// printk("control pkt bdp / 2:%d\n", nd_params.control_pkt_bdp / 2);
		if(pq_empty) {
			entry->state = ND_IDLE;
			rcv_core_tab.num_active_cores -= 1;
			// printk("pq empty reach here:%d\n", __LINE__);
			rcv_invoke_next(&rcv_core_tab);
		} else if (rcv_core_tab.num_active_cores < MAX_ACTIVE_CORE) {
			bool find_flow;
			/* send next token in the same core */
			spin_unlock(&rcv_core_tab.lock);
			// printk("reach here:%d\n", __LINE__);

			find_flow = nd_xmit_token_single_core(entry);
			// if(!find_flow) {
			// 	entry->state = ND_IDLE;
			// 	printk("reach here:%d\n", __LINE__);
			// 	goto not_find_flow;
			// }
			/* not enough pkt is granted */
			if(atomic_read(&entry->remaining_tokens) <= nd_params.control_pkt_bdp / 2) {
				entry->state = ND_IDLE;
				// printk("reach here:%d\n", __LINE__);
				goto not_find_flow;
			}
			goto end;
		} else {
			entry->state = ND_IN_QUEUE;
			rcv_core_tab.num_active_cores -= 1;
			// printk("reach here:%d\n", __LINE__);
			list_add_tail(&entry->list_link, &rcv_core_tab.sche_list);
			rcv_invoke_next(&rcv_core_tab);
		}
		spin_unlock(&rcv_core_tab.lock);
		// hrtimer_start(&nd_epoch.token_xmit_timer, ktime_set(0, 0), HRTIMER_MODE_REL_PINNED_SOFT);
	}
end:
	return;

not_find_flow:
	spin_lock(&rcv_core_tab.lock);
	rcv_core_tab.num_active_cores -= 1;
	rcv_invoke_next(&rcv_core_tab);
	spin_unlock(&rcv_core_tab.lock);
}

/* handle flowlet done, flow came back after timeour or retranmission; */
enum hrtimer_restart flowlet_done_event(struct hrtimer *timer) {
	// struct nd_grant* grant, temp;
	struct rcv_core_entry *entry = container_of(timer, struct rcv_core_entry, flowlet_done_timer);
	WARN_ON(!in_softirq());
	// printk("flowlet done timer is called\n");

	spin_lock(&entry->lock);
	/* reset the remaining tokens to zero */
	if(entry->state == ND_ACTIVE) {
		rcv_flowlet_done(entry);
	} else if(entry->state == ND_IDLE && !nd_pq_empty(&entry->flow_q)) {
		bool find_flow = false;
		spin_lock(&rcv_core_tab.lock);
		/* list empty*/
		if(rcv_core_tab.num_active_cores < MAX_ACTIVE_CORE) {
			rcv_core_tab.num_active_cores += 1;
			entry->state = ND_ACTIVE;
			spin_unlock(&rcv_core_tab.lock);
			// printk("reach here:%d\n", __LINE__);
			find_flow = nd_xmit_token_single_core(entry);
			// if(!find_flow) {
			// 	entry->state = ND_IDLE;
			// 	printk("reach here:%d\n", __LINE__);

			// 	goto not_find_flow;
			// }
			/* not enough pkt is granted */
			if(atomic_read(&entry->remaining_tokens) <= nd_params.control_pkt_bdp / 2) {
				entry->state = ND_IDLE;
				// printk("reach here:%d\n", __LINE__);
				goto not_find_flow;
			}
			goto end;
		} else {
			entry->state = ND_IN_QUEUE;
			list_add_tail(&entry->list_link, &rcv_core_tab.sche_list);
		}
		spin_unlock(&rcv_core_tab.lock);
	}
end:
	spin_unlock(&entry->lock);
 	// queue_work(nd_epoch.wq, &nd_epoch.token_xmit_struct);
	return HRTIMER_NORESTART;

not_find_flow:
	spin_unlock(&entry->lock);
	spin_lock(&rcv_core_tab.lock);
	rcv_core_tab.num_active_cores -= 1;
	rcv_invoke_next(&rcv_core_tab);
	spin_unlock(&rcv_core_tab.lock);
	return HRTIMER_NORESTART;

}


void xmit_core_entry_init(struct xmit_core_entry *entry, int core_id) {
	spin_lock_init(&entry->lock);
	/* token xmit timer*/
	// atomic_set(&epoch->pending_flows, 0);
	entry->core_id = core_id;
	// hrtimer_init(&entry->token_xmit_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED_SOFT);
	// entry->token_xmit_timer.function = &nd_token_xmit_event;
	// hrtimer_init(&entry->data_xmit_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED_SOFT);
	// entry->data_xmit_timer.function = &nd_xmit_data_event;
	skb_queue_head_init(&entry->token_q);

	INIT_LIST_HEAD(&entry->list_link);
	INIT_WORK(&entry->data_xmit_struct, nd_xmit_data_event);
}

int xmit_core_table_init(struct xmit_core_table *tab) {
	int i;
	tab->num_active_cores = 0;
	spin_lock_init(&tab->lock);
	INIT_LIST_HEAD(&tab->sche_list);
	tab->wq = alloc_workqueue("nd-xmit-wq",
		WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
	if(!tab->wq) 
		return -ENOMEM;

	for (i = 0; i < NR_CPUS; i++) {
		xmit_core_entry_init(&tab->table[i], i);
	}
	return 0;
}

void xmit_core_table_destory(struct xmit_core_table *tab) {
	flush_workqueue(tab->wq);
	destroy_workqueue(tab->wq);
}
int xmit_use_token(struct sk_buff* skb) {
	struct nd_token_hdr *th;
	struct sock* sk;
	struct nd_sock *dsk;
	// int sdif = inet_sdif(skb);
	// bool refcounted = false;
	int sent_bytes = 0;

	th = nd_token_hdr(skb);
	// sk = __nd_lookup_skb(&nd_hashinfo, skb, __nd_hdrlen(&th->common), th->common.source,
 //            th->common.dest, sdif, &refcounted);
	sk = skb->sk;
	if(sk) {
		// printk("reach here:%d\n", __LINE__);
		// printk("use token\n");
	 	dsk = nd_sk(sk);
 		bh_lock_sock(sk);
		/* add token */
 		dsk->grant_nxt = th->grant_nxt > dsk->grant_nxt ? th->grant_nxt : dsk->grant_nxt;
 		/* add sack info */
 		nd_get_sack_info(sk, skb);
	    if(!sock_owned_by_user(sk) || dsk->num_sacks == 0) {
	 		sent_bytes += nd_write_timer_handler(sk);
	    } else {
	 		test_and_set_bit(ND_RTX_DEFERRED, &sk->sk_tsq_flags);
	    }
	    bh_unlock_sock(sk);
	}
	// if (refcounted) {
 //        sock_put(sk);
 //    }
	kfree_skb(skb);
	return sent_bytes;
}

/* Assume table lock is hold*/
void xmit_invoke_next(struct xmit_core_table *tab) {
	if (!list_empty(&tab->sche_list)) {
		struct xmit_core_entry *next_entry = list_first_entry(&tab->sche_list, struct xmit_core_entry, list_link);
		// WARN_ON(next_entry == entry);
		// WARN_ON(skb_queue_empty(next_entry->token_q));
		list_del_init(&next_entry->list_link);
		tab->num_active_cores += 1;
		// printk("invoke next CPU Core:%d\n", raw_smp_processor_id());
		queue_work_on(next_entry->core_id, tab->wq, &next_entry->data_xmit_struct);
		// hrtimer_start(&next_entry->data_xmit_timer, ns_to_ktime(0), 
		// HRTIMER_MODE_REL_PINNED_SOFT);
	}
}
void xmit_handle_new_token(struct xmit_core_table *tab, struct sk_buff* skb) {
	bool send_now = false;
	bool is_empty = false;
	int core_id = nd_sk(skb->sk)->core_id;
	struct xmit_core_entry *entry = &tab->table[core_id];
	struct sk_buff* new_skb;
	spin_lock(&entry->lock);
	if(skb_queue_empty(&entry->token_q))
		is_empty = true;

	// 	printk("push the skb\n");
	__skb_queue_tail(&entry->token_q, skb);
	// }	
	// printk("entry->token q is_empty:%d\n", skb_queue_empty(&entry->token_q));
	if(is_empty) {
		/* Deadlock won't happen because entry is not in sche_list yet*/
		spin_lock(&tab->lock);
		if(tab->num_active_cores < MAX_ACTIVE_CORE) {
			tab->num_active_cores += 1;
			send_now = true;
		}
		else {
			list_add_tail(&entry->list_link, &tab->sche_list);
		}
		spin_unlock(&tab->lock);
		if(send_now) {
			new_skb = __skb_dequeue(&entry->token_q);
			WARN_ON(new_skb != skb);
			xmit_use_token(skb);
			spin_lock(&tab->lock);
			tab->num_active_cores -= 1;
			xmit_invoke_next(tab);
			spin_unlock(&tab->lock);
		}
		// xmit_invoke_next(tab);
	}

	spin_unlock(&entry->lock);
	return;
}

/* In Process Context */
void nd_xmit_data_event(struct work_struct *w) {
	// struct nd_grant* grant, temp;
	int num_bytes_sent;
	struct xmit_core_entry *entry = container_of(w, struct xmit_core_entry, data_xmit_struct);

	// printk("xmit data timer handler is called: %d\n", raw_smp_processor_id());
	/* reset the remaining tokens to zero */
	// atomic_set(&epoch->remaining_tokens, 0);	
start_sent:
	num_bytes_sent = 0;
	while(1) {
		struct sk_buff* skb;
		spin_lock_bh(&entry->lock);
		if(num_bytes_sent > nd_params.data_budget) {
			goto stop;
		}
		if(skb_queue_empty(&entry->token_q)) {
			goto stop;
		}
		skb = __skb_dequeue(&entry->token_q);
		spin_unlock_bh(&entry->lock);
		local_bh_disable();
		num_bytes_sent += xmit_use_token(skb);
		local_bh_enable();
		continue;
	stop:
		spin_unlock_bh(&entry->lock);
		break;
	}
	spin_lock_bh(&entry->lock);
	spin_lock_bh(&xmit_core_tab.lock);

	if (!skb_queue_empty(&entry->token_q)) {
		if(xmit_core_tab.num_active_cores < MAX_ACTIVE_CORE) {
			spin_unlock_bh(&entry->lock);
			spin_unlock_bh(&xmit_core_tab.lock);
			goto start_sent;
		}
		/* add this entry back to the schedule list */
		list_add_tail(&entry->list_link, &xmit_core_tab.sche_list);

	}
	xmit_core_tab.num_active_cores -= 1;
	
	xmit_invoke_next(&xmit_core_tab);
	spin_unlock_bh(&xmit_core_tab.lock);
	spin_unlock_bh(&entry->lock);
 	// queue_work(nd_epoch.wq, &nd_epoch.token_xmit_struct);
	return;

}
// bool xmit_finish() {
// 	int core_id = raw_smp_processor_id();
// 	struct xmit_core_entry *entry = &tab->table[core_id];
// 	return false;
// }