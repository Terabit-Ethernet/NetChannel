#include "nd_data_copy.h"
#include "nd_impl.h"

static struct workqueue_struct *nd_dcopy_wq;

static struct nd_dcopy_queue nd_dcopy_q[NR_CPUS];


static inline void nd_dcopy_free_request(struct nd_dcopy_request *req) {
    if(req->clean_skb){
		// pr_info("reach here:%d\n", __LINE__);
        kfree_skb(req->skb);
	}

	if(!req->bv_arr) {
		nd_release_pages(req->bv_arr, true, req->max_segs);
		kfree(req->bv_arr);
	}
	// pr_info("reach here:%d\n", __LINE__);
    // kfree(req->iter.bvec);
	// pr_info("reach here:%d\n", __LINE__);
    kfree(req);
}

static inline void nd_dcopy_clean_req(struct nd_dcopy_queue *queue)
{

	/* pdu doesn't have to be freed */
	// kfree(queue->request->pdu);
	// put_page(queue->request->hdr);
	// page_frag_free(queue->request->hdr);
	// kfree(queue->request);
    nd_dcopy_free_request(queue->request);
	queue->request = NULL;
	
}

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

bool nd_dcopy_queue_request(struct nd_dcopy_request *req) {
    struct nd_dcopy_queue* queue = &nd_dcopy_q[req->io_cpu];
    bool empty = false;
    
    empty = llist_add(&req->lentry, &queue->req_list) &&
		list_empty(&queue->copy_list) && !queue->request;
    
	if (queue->io_cpu == smp_processor_id() &&
	     empty && mutex_trylock(&queue->copy_mutex)) {
		// queue->more_requests = !last;
		nd_try_dcopy(queue);
		// if(ret == -EAGAIN)
		// 	queue->more_requests = false;
		mutex_unlock(&queue->copy_mutex);
	} else {
		/* data packets always go here */	
		queue_work_on(queue->io_cpu, nd_dcopy_wq, &queue->io_work);
	}
    return true;
}

int nd_try_dcopy(struct nd_dcopy_queue *queue)
{
	struct nd_dcopy_request *req;
    struct nd_sock *nsk;
	int ret = 1, err, remaining_bytes, req_len;
    u32 offset;

	if (!queue->request) {
		queue->request = nd_dcopy_fetch_request(queue);
		if (!queue->request)
			return 0;
	} else {
		WARN_ON(true);
	}
    req = queue->request;
    nsk = nd_sk(req->sk);
    /*perform data copy */
    // lock_sock(req->sk);
    // pr_info("doing data copy\n");
	// pr_info("req addr:%p\n", req);
	// pr_info("req iter:%p\n", req->iter);
	// pr_info("req iter bvec:%p\n", req->iter.bvec);

    err = skb_copy_datagram_iter(req->skb, req->offset, &req->iter, req->len);
    // release_sock(req->sk);
    if (err) {
    /* Exception. Bailout! */
        // if (!copied)
		// 			copied = -EFAULT;
		// 		break;
        // pr_info("err:%d\n", err);
        // pr_info("skb_headlen(skb):%d\n", skb_headlen(req->skb));
	    // pr_info("warning core:%d\n", raw_smp_processor_id());
        // pr_info("skb seq:%u\n", ND_SKB_CB(req->skb)->seq);
        // pr_info("skb->len:%d\n", req->skb->len);
        // pr_info("req->offset:%u\n", req->offset);
        // pr_info("req->len:%d\n", req->len);
	    skb_dump(KERN_WARNING, req->skb, false);
        pr_info("msg->mssg_iter.type:%ld\n", req->iter.type &4);

		pr_info("msg->mssg_iter.count:%ld\n", req->iter.count);
		pr_info("msg->mssg_iter.iov_offset:%ld\n", req->iter.iov_offset);
		pr_info("msg->mssg_iter.iov_offset:%p\n", req->iter.iov);
		pr_info("msg->mssg_iter.nr_segs:%ld\n", req->iter.nr_segs);
		pr_info("msg->mssg_iter.iov_base:%p\n", req->iter.iov->iov_base);
		pr_info("msg->mssg_iter.iov_len:%ld\n", req->iter.iov->iov_len);

        WARN_ON(true);
    }
    // pr_info("err:%d\n", err);
	req_len = req->len;
	// if (req->state == ND_CONN_SEND_CMD_PDU) {
	// 	ret = nd_conn_try_send_cmd_pdu(req);
	// 	if (ret <= 0)
	// 		goto done;
	// 	if (req->state == ND_CONN_PDU_DONE)
	// 		goto clean;
	// }

	
	// if (req->state == ND_CONN_SEND_DATA) {
	// 	// printk("send data pdu\n");
	// 	ret = nd_conn_try_send_data_pdu(req);
	// 	if (ret <= 0)
	// 		goto done;
	// 	if (ret == 1) {
	// 		atomic_dec(&queue->cur_queue_size);
	// 	}
	// }

	// if (req->state == NVME_TCP_SEND_DATA) {
	// 	ret = nvme_tcp_try_send_data(req);
	// 	if (ret <= 0)
	// 		goto done;
	// }
clean:
	// pr_info("request->len: -%d\n", req_len);
    nd_dcopy_clean_req(queue);
    remaining_bytes = atomic_sub_return(req_len, &nsk->receiver.in_flight_copy_bytes);
    // pr_info("remaining bytes:%d \n", remaining_bytes);
	// if (req->state == NVME_TCP_SEND_DDGST)
	// 	ret = nvme_tcp_try_send_ddgst(req);
    if(remaining_bytes == 0) {
        lock_sock(req->sk);
        req->sk->sk_data_ready(req->sk);
        release_sock(req->sk);
    }
done:
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
	// queue->queue_size = queue_size;
	// atomic_set(&queue->cur_queue_size, 0);
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
