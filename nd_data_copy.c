#include "nd_data_copy.h"
#include "nd_impl.h"

static struct workqueue_struct *nd_dcopy_wq;

static struct nd_dcopy_queue nd_dcopy_q[NR_CPUS];


static inline void nd_dcopy_free_request(struct nd_dcopy_request *req) {
    if(req->clean_skb && req->skb){
		// pr_info("reach here:%d\n", __LINE__);
        kfree_skb(req->skb);
	}

	if(req->bv_arr) {
		// nd_release_pages(req->bv_arr, true, req->max_segs);
		kfree(req->bv_arr);
		req->bv_arr = NULL;
	}
	// pr_info("reach here:%d\n", __LINE__);
    // kfree(req->iter.bvec);
	// pr_info("reach here:%d\n", __LINE__);
    kfree(req);
}

// static inline void nd_dcopy_clean_req(struct nd_dcopy_request *req)
// {

// 	/* pdu doesn't have to be freed */
// 	// kfree(queue->request->pdu);
// 	// put_page(queue->request->hdr);
// 	// page_frag_free(queue->request->hdr);
// 	// kfree(queue->request);
//     nd_dcopy_free_request(request);	
// }

static void nd_dcopy_process_req_list(struct nd_dcopy_queue *queue)
{
	struct nd_dcopy_request *req;
	struct llist_node *node;

	for (node = llist_del_all(&queue->req_list); node; node = node->next) {
		req = llist_entry(node, struct nd_dcopy_request, lentry);
		list_add(&req->entry, &queue->copy_list);
	}
}

static inline struct nd_dcopy_request *
nd_dcopy_fetch_request(struct nd_dcopy_queue *queue)
{
	struct nd_dcopy_request *req;

	req = list_first_entry_or_null(&queue->copy_list,
			struct nd_dcopy_request, entry);
	if (!req) {
		nd_dcopy_process_req_list(queue);
		req = list_first_entry_or_null(&queue->copy_list,
				struct nd_dcopy_request, entry);
		if (unlikely(!req))
			return NULL;
	}

	list_del(&req->entry);
	return req;
}

/* round-robin */
int nd_dcopy_sche_rr(void) {
	struct nd_dcopy_queue *queue;
	static u32 last_q = 0;
	int i = 0, qid;
	bool find = false;
	for (i = 1; i <= nd_params.nd_num_dc_thread; i++) {

		qid = (i + last_q) % (nd_params.nd_num_dc_thread);
		queue =  &nd_dcopy_q[qid * 4 + nd_params.data_cpy_core];
		// if(nd_params.nd_debug)
		// 	pr_info("qid:%d queue size:%d \n",qid, atomic_read(&queue->cur_queue_size));
		if(atomic_read(&queue->cur_queue_size) >= queue->queue_size)
			continue;
		find = true;
		last_q = qid;
		break;
		// return qid * 4 + nd_params.data_cpy_core;
	}
	if(!find) {
		qid = (1 + last_q) % (nd_params.nd_num_dc_thread);
		last_q = qid;
	}
	return last_q * 4 + nd_params.data_cpy_core;
	// }
	// return -1;
}

/* compact */
int nd_dcopy_sche_compact(void) {
	struct nd_dcopy_queue *queue;
	static u32 last_q = 0;
	int i = 0, qid;
	bool find = false;
	for (i = 0; i < nd_params.nd_num_dc_thread; i++) {

		qid = (i) % (nd_params.nd_num_dc_thread);
		queue =  &nd_dcopy_q[qid * 4 + nd_params.data_cpy_core];
		// if(nd_params.nd_debug)
		// 	pr_info("qid:%d queue size:%d \n",qid, atomic_read(&queue->cur_queue_size));
		if(atomic_read(&queue->cur_queue_size) >= queue->queue_size) {
			// pr_info(" queue size is larger than limit:%d %d\n", i, atomic_read(&queue->cur_queue_size));
			continue;
		}
		find = true;
		last_q = qid;
		break;
		// return qid * 4 + nd_params.data_cpy_core;
	}
	/* if all queue is full; do round-robin */
	if(!find) {
		qid = (1 + last_q) % (nd_params.nd_num_dc_thread);
		last_q = qid;
	}
	return last_q * 4 + nd_params.data_cpy_core;
	// }
	// return -1;
}

int nd_dcopy_queue_request(struct nd_dcopy_request *req) {
	int qid;
    struct nd_dcopy_queue* queue;  
    bool empty = false;
    if(req->io_cpu >= 0){
		qid = req->io_cpu;
		queue = &nd_dcopy_q[req->io_cpu];
	}
	else {
		qid = nd_dcopy_sche_rr();
		queue = &nd_dcopy_q[qid];
	}
	atomic_add(req->remain_len, &queue->cur_queue_size);
	// if(nd_params.nd_debug)
	// 	pr_info("qid:%d\n",qid);
	req->queue = queue;
    empty = llist_add(&req->lentry, &queue->req_list) &&
		list_empty(&queue->copy_list) && !queue->request;
    
	// if (queue->io_cpu == smp_processor_id() &&
	//      empty && mutex_trylock(&queue->copy_mutex)) {
	// 	// queue->more_requests = !last;
	// 	nd_try_dcopy(queue);
	// 	// if(ret == -EAGAIN)
	// 	// 	queue->more_requests = false;
	// 	mutex_unlock(&queue->copy_mutex);
	// } else {
		/* data packets always go here */	
		queue_work_on(queue->io_cpu, nd_dcopy_wq, &queue->io_work);
	// }
    return qid;
}

void nd_try_dcopy_receive(struct nd_dcopy_request *req) {
    struct nd_sock *nsk;
 	int err, req_len;

	nsk = nd_sk(req->sk);
	err = skb_copy_datagram_iter(req->skb, req->offset, &req->iter, req->remain_len);
    if (err) {
    /* Exception. Bailout! */
	    skb_dump(KERN_WARNING, req->skb, false);
        // pr_info("msg->mssg_iter.type:%ld\n", req->iter.type &4);
		// pr_info("msg->mssg_iter.count:%ld\n", req->iter.count);
		// pr_info("msg->mssg_iter.iov_offset:%ld\n", req->iter.iov_offset);
		// pr_info("msg->mssg_iter.iov_offset:%p\n", req->iter.iov);
		// pr_info("msg->mssg_iter.nr_segs:%ld\n", req->iter.nr_segs);
		// pr_info("msg->mssg_iter.iov_base:%p\n", req->iter.iov->iov_base);
		// pr_info("msg->mssg_iter.iov_len:%ld\n", req->iter.iov->iov_len);
        WARN_ON(true);
    }
    // pr_info("err:%d\n", err);
	req_len = req->remain_len;
// clean:
    // nd_dcopy_free_request(req);
	req->state = ND_DCOPY_DONE;
	/* release the page before reducing the count */
	if(req->bv_arr || req->clean_skb) {
		struct nd_dcopy_page* resp = kmalloc(sizeof(struct nd_dcopy_page), GFP_KERNEL);
		if(req->bv_arr) {
			resp->max_segs = req->max_segs;
			resp->bv_arr = req->bv_arr;
			req->bv_arr = NULL;
		} else {
			resp->bv_arr = NULL;
		}
		if(req->clean_skb) {
			resp->skb = req->skb;
			req->skb = NULL;
		} else {
			resp->skb = NULL;
		}
		llist_add(&resp->lentry, &nsk->receiver.clean_page_list);
		// nd_release_pages(req->bv_arr, true, req->max_segs);
	} 
    atomic_sub_return(req_len, &nsk->receiver.in_flight_copy_bytes);
	atomic_sub(req_len, &req->queue->cur_queue_size);
// done:
// 	return ret;
}

static inline int nd_copy_to_page_nocache(struct sock *sk, struct iov_iter *from,
					   struct sk_buff *skb,
					   struct page *page,
					   int off, int copy)
{
	int err;

	err = skb_do_copy_data_nocache(sk, skb, from, page_address(page) + off,
				       copy, skb->len);
	if (err)
		return err;

	skb->len	     += copy;
	skb->data_len	     += copy;
	skb->truesize	     += copy;
	// sk_wmem_queued_add(sk, copy);
	// sk_mem_charge(sk, copy);
	return 0;
}

void nd_try_dcopy_send(struct nd_dcopy_request *req) {
    struct nd_sock *nsk;
 	int err, req_len, i;
	size_t copy;
	struct page_frag *pfrag = &current->task_frag;
	struct sk_buff *skb;
	struct nd_dcopy_response *resp;
	req_len = req->remain_len; 
	nsk = nd_sk(req->sk);
	WARN_ON(req_len == 0);
	while(req_len > 0) {
		bool merge = true;
		if (!skb_page_frag_refill(32U, pfrag, req->sk->sk_allocation)) {
			goto wait_for_memory;
		}
		skb = req->skb;
		if(!skb) 
			goto create_new_skb;
		if(skb->len == USHRT_MAX)
			goto push_skb;
		i = skb_shinfo(skb)->nr_frags;
		if (!skb_can_coalesce(skb, i, pfrag->page,
			 pfrag->offset)) {
			if (i == MAX_SKB_FRAGS) {
				goto push_skb;
			}
			merge = false;
		}
		copy = min_t(int, USHRT_MAX - skb->len, req_len);
		copy = min_t(int, copy,
			     pfrag->size - pfrag->offset);
		err = nd_copy_to_page_nocache(req->sk, &req->iter, skb,
					       pfrag->page,
					       pfrag->offset,
					       copy);
		if(err)
			WARN_ON(true);
		/* Update the skb. */
		if (merge) {
			skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
		} else {
			skb_fill_page_desc(skb, i, pfrag->page,
					   pfrag->offset, copy);
			get_page(pfrag->page);
		}
		pfrag->offset += copy;
		req_len -= copy;
		/* last request */
		if(req_len == 0)
			goto push_skb;
		continue;

	create_new_skb:
		skb = alloc_skb(0, req->sk->sk_allocation);
		WARN_ON(req->skb != NULL);
		req->skb = skb;
		// printk("create new skb\n");
		if(!skb)
			goto wait_for_memory;

		// __skb_queue_tail(&sk->sk_write_queue, skb);
		continue;

	push_skb:
		/* push the new skb */
		ND_SKB_CB(skb)->seq = req->seq;
		resp = kmalloc(sizeof(struct nd_dcopy_response), GFP_KERNEL);
		resp->skb = req->skb;
		llist_add(&resp->lentry, &nsk->sender.response_list);
		req->seq += skb->len;
		req->skb = NULL;
		resp = NULL;
		continue;

	wait_for_memory:
		WARN_ON(true);
		break;
	}
	if(req_len == 0) {
		req->state = ND_DCOPY_DONE;
		nd_release_pages(req->bv_arr, true, req->max_segs);
	}  
	atomic_sub_return(req->remain_len - req_len, &nsk->sender.in_flight_copy_bytes);
	atomic_sub(req->remain_len - req_len, &req->queue->cur_queue_size);
	req->remain_len = req_len;
// done:
// 	return ret;
}

int nd_try_dcopy(struct nd_dcopy_queue *queue)
{
	struct nd_dcopy_request *req;
    // struct nd_sock *nsk;
	int ret = 1;
    // u32 offset;

	if (!queue->request) {
		queue->request = nd_dcopy_fetch_request(queue);
		if (!queue->request)
			return 0;
	} else {
		WARN_ON(true);
	}
    req = queue->request;

	if(req->state == ND_DCOPY_RECV) {
		nd_try_dcopy_receive(req);

	} 
	if(req->state == ND_DCOPY_SEND) {
		nd_try_dcopy_send(req);
	}
	if(req->state == ND_DCOPY_DONE) {
		// atomic_dec(&queue->cur_queue_size);
		nd_dcopy_free_request(req);
		queue->request = NULL;
	}
    /*perform data copy */
    // lock_sock(req->sk);
    // pr_info("doing data copy\n");
	// pr_info("req addr:%p\n", req);
	// pr_info("req iter:%p\n", req->iter);
	// pr_info("req iter bvec:%p\n", req->iter.bvec);

    // err = skb_copy_datagram_iter(req->skb, req->offset, &req->iter, req->len);
    // release_sock(req->sk);

	return ret;
}

void nd_dcopy_io_work(struct work_struct *w)
{
	struct nd_dcopy_queue *queue =
		container_of(w, struct nd_dcopy_queue, io_work);
	unsigned long deadline = jiffies + msecs_to_jiffies(1);
	int ret;
	bool pending;
	do {
		int result;
		pending = false;
		mutex_lock(&queue->copy_mutex);
		result = nd_try_dcopy(queue);
		mutex_unlock(&queue->copy_mutex);
		if (result > 0)
			pending = true;
		else if (unlikely(result < 0))
			break;
		

		// result = nvme_tcp_try_recv(queue);
		// if (result > 0)
		// 	pending = true;
		// else if (unlikely(result < 0))
		// 	return;
		if (!pending)
			break;

	} while (!time_after(jiffies, deadline)); /* quota is exhausted */
	if(pending)
		ret = queue_work_on(queue->io_cpu, nd_dcopy_wq, &queue->io_work);
}

void nd_dcopy_flush_req_list(struct nd_dcopy_queue *queue) {
    struct nd_dcopy_request *req, *temp;
    list_for_each_entry_safe(req, temp, &queue->copy_list, entry) {
        nd_dcopy_free_request(req);
    }
	INIT_LIST_HEAD(&queue->copy_list);
}

void nd_dcopy_free_queue(struct nd_dcopy_queue *queue)
{
	// struct nd_conn_queue *queue = &ctrl->queues[qid];

	// if (!test_and_clear_bit(ND_CONN_Q_LIVE, &queue->flags))
	// 	return;
	cancel_work_sync(&queue->io_work);
    /* flush all pending request and clean the occupied memory of each req */
    nd_dcopy_process_req_list(queue);
    mutex_lock(&queue->copy_mutex);
    nd_dcopy_flush_req_list(queue);
    mutex_unlock(&queue->copy_mutex);

}

int nd_dcopy_alloc_queue(struct nd_dcopy_queue *queue, int io_cpu)
{
    init_llist_head(&queue->req_list);
	INIT_LIST_HEAD(&queue->copy_list);
	// spin_lock_init(&queue->lock);
    mutex_init(&queue->copy_mutex);
	INIT_WORK(&queue->io_work, nd_dcopy_io_work);
    queue->io_cpu = io_cpu;
	queue->queue_size = 128 * 65536;
	// queue->queue_size = queue_size;
	atomic_set(&queue->cur_queue_size, 0);
	return 0;
}

int nd_dcopy_alloc_queues(struct nd_dcopy_queue *queues)
{
	int i, ret;

	for (i = 0; i < NR_CPUS; i++) {
		ret = nd_dcopy_alloc_queue(&queues[i], i);
		if (ret)
			goto out_free_queues;
	}

	return 0;

out_free_queues:
	for (i--; i >= 0; i--)
		nd_dcopy_free_queue(&queues[i]);

	return ret;
}

int nd_dcopy_init(void)
{
	int ret;

	nd_dcopy_wq = alloc_workqueue("nd_dcopy_wq", WQ_MEM_RECLAIM , 0);

	if (!nd_dcopy_wq)
		return -ENOMEM;
	ret= nd_dcopy_alloc_queues(nd_dcopy_q);
	// ndt_port = kzalloc(sizeof(*ndt_port), GFP_KERNEL);

	// ret = nvmet_register_transport(&nvmet_tcp_ops);


	if (ret)
	 	goto err;

	return 0;
err:
	destroy_workqueue(nd_dcopy_wq);
	return ret;
}

void nd_dcopy_exit(void)
{
	// struct ndt_conn_queue *queue;

	// nvmet_unregister_transport(&nvmet_tcp_ops);
    int i;
    pr_info("exit data copy \n");
	flush_scheduled_work();
	for (i = 0; i >= 0; i--)
		nd_dcopy_free_queue(&nd_dcopy_q[i]);
	// mutex_lock(&ndt_conn_queue_mutex);
	// list_for_each_entry(queue, &ndt_conn_queue_list, queue_list)
	// 	kernel_sock_shutdown(queue->sock, SHUT_RDWR);
	// mutex_unlock(&ndt_conn_queue_mutex);
	// flush_scheduled_work();

	destroy_workqueue(nd_dcopy_wq);
}
