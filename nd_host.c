#include "nd_host.h"
#include "nd_impl.h"
// static LIST_HEAD(nd_conn_ctrl_list);
static DEFINE_MUTEX(nd_conn_ctrl_mutex);
static struct workqueue_struct *nd_conn_wq;
static struct workqueue_struct *nd_conn_wq_lat;
static struct workqueue_struct *sock_wait_wq;

// struct nd_conn_ctrl* nd_ctrl;
// static struct blk_mq_ops nvme_tcp_mq_ops;
// static struct blk_mq_ops nvme_tcp_admin_mq_ops;

/*  conn_table is read-only for now so that we don't need lock in the hot path; 
TO DO: add the lock once the dynamic adding/removing logic has been added.
This also requires the change of ctrl->io_queue logic. 
*/
/* conn_table has 2^8 slots */
DECLARE_HASHTABLE(nd_conn_table, 8);

static inline bool nd_conn_has_inline_data(struct nd_conn_request *req) {
	struct ndhdr* hdr = req->hdr;
	return hdr->type == DATA;
}

static inline int nd_conn_queue_id(struct nd_conn_queue *queue)
{
	return queue - queue->ctrl->queues;
}

static inline bool nd_conn_queue_is_lat(struct nd_conn_queue *queue)
{
	return queue->prio_class == 1;
}

static inline void nd_conn_done_send_req(struct nd_conn_queue *queue)
{
	struct ndhdr* hdr = queue->request->hdr;
	if(hdr->type == DATA) 
		kfree_skb(queue->request->skb);
	/* pdu doesn't have to be freed */
	// kfree(queue->request->pdu);
	// put_page(queue->request->hdr);
	page_frag_free(queue->request->hdr);
	kfree(queue->request);
	queue->request = NULL;
	
}

static inline bool nd_conn_queue_more(struct nd_conn_queue *queue)
{
	return !list_empty(&queue->send_list) ||
		!llist_empty(&queue->req_list) || queue->more_requests;
}

void nd_conn_restore_sock_calls(struct nd_conn_queue *queue)
{
	struct socket *sock = queue->sock;

	write_lock_bh(&sock->sk->sk_callback_lock);
	sock->sk->sk_user_data  = NULL;
	sock->sk->sk_data_ready = queue->data_ready;
	sock->sk->sk_state_change = queue->state_change;
	sock->sk->sk_write_space  = queue->write_space;
	write_unlock_bh(&sock->sk->sk_callback_lock);
}

void __nd_conn_stop_queue(struct nd_conn_queue *queue)
{
	kernel_sock_shutdown(queue->sock, SHUT_RDWR);
	nd_conn_restore_sock_calls(queue);
	cancel_work_sync(&queue->io_work);
}

void nd_conn_stop_queue(struct nd_conn_ctrl *ctrl, int qid)
{
	struct nd_conn_queue *queue = &ctrl->queues[qid];

	if (!test_and_clear_bit(ND_CONN_Q_LIVE, &queue->flags))
		return;
	__nd_conn_stop_queue(queue);
}

void nd_conn_free_queue(struct nd_conn_ctrl *ctrl, int qid)
{
	// struct nvme_tcp_ctrl *ctrl = to_tcp_ctrl(nctrl);
	struct nd_conn_queue *queue = &ctrl->queues[qid];

	if (!test_and_clear_bit(ND_CONN_Q_ALLOCATED, &queue->flags))
		return;

	// if (queue->hdr_digest || queue->data_digest)
	// 	nvme_tcp_free_crypto(queue);

	sock_release(queue->sock);
	if(queue->request)
		nd_conn_done_send_req(queue);
	// kfree(queue->pdu);
}

void nd_conn_free_io_queues(struct nd_conn_ctrl *ctrl)
{
	int i;

	for (i = 0; i < ctrl->queue_count; i++)
		nd_conn_free_queue(ctrl, i);
}

int nd_conn_start_queue(struct nd_conn_ctrl *ctrl, int idx)
{
	// struct nvme_tcp_ctrl *ctrl = to_tcp_ctrl(nctrl);
	int ret = 0;

	// if (idx)
	// 	ret = nvmf_connect_io_queue(nctrl, idx, false);
	// else
	// 	ret = nvmf_connect_admin_queue(nctrl);

	// if (!ret) {
		set_bit(ND_CONN_Q_LIVE, &ctrl->queues[idx].flags);

	// } else {
	// 	if (test_bit(NVME_TCP_Q_ALLOCATED, &ctrl->queues[idx].flags))
	// 		__nvme_tcp_stop_queue(&ctrl->queues[idx]);
	// 	dev_err(nctrl->device,
	// 		"failed to connect queue: %d ret=%d\n", idx, ret);
	// }
	return ret;
}

void nd_conn_stop_io_queues(struct nd_conn_ctrl *ctrl)
{
	int i;

	for (i = 0; i < ctrl->queue_count; i++)
		nd_conn_stop_queue(ctrl, i);
}

void nd_conn_data_ready(struct sock *sk)
{
	struct nd_conn_queue *queue;

	read_lock_bh(&sk->sk_callback_lock);
	queue = sk->sk_user_data;
	if (likely(queue && queue->rd_enabled) &&
	    !test_bit(ND_CONN_Q_POLLING, &queue->flags)) {
			if(nd_conn_queue_is_lat(queue)) {
				queue_work_on(queue->io_cpu, nd_conn_wq_lat, &queue->io_work);
			}else {
				queue_work_on(queue->io_cpu, nd_conn_wq, &queue->io_work);
			}
		}
	read_unlock_bh(&sk->sk_callback_lock);
}

void nd_conn_write_space(struct sock *sk)
{
	struct nd_conn_queue *queue;

	read_lock_bh(&sk->sk_callback_lock);
	queue = sk->sk_user_data;
	if (likely(queue && sk_stream_is_writeable(sk))) {
		// printk("write space invoke\n");
		clear_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
			if(nd_conn_queue_is_lat(queue)) {
				queue_work_on(queue->io_cpu, nd_conn_wq_lat, &queue->io_work);
			}else {
				queue_work_on(queue->io_cpu, nd_conn_wq, &queue->io_work);
			}
	}
	read_unlock_bh(&sk->sk_callback_lock);
}

void nd_conn_state_change(struct sock *sk)
{
	struct nd_conn_queue *queue;

	read_lock(&sk->sk_callback_lock);
	queue = sk->sk_user_data;
	if (!queue)
		goto done;

	switch (sk->sk_state) {
	case TCP_CLOSE:
	case TCP_CLOSE_WAIT:
	case TCP_LAST_ACK:
	case TCP_FIN_WAIT1:
	case TCP_FIN_WAIT2:
        // this part might have issue
        pr_info("TCP state change:%d\n", sk->sk_state);
		// nd_conn_error_recovery(&ctrl);
		break;
	default:
		pr_info("queue %d socket state %d\n",
			nd_conn_queue_id(queue), sk->sk_state);
	}

	queue->state_change(sk);
done:
	read_unlock(&sk->sk_callback_lock);
}

/* round-robin; will not select the previous one except if there is only one channel. */
int nd_conn_sche_rr(struct nd_conn_queue* queues, int last_q, int cur_count, int prio_class, bool avoid_check) {
	struct nd_conn_queue *queue;
	/* cur_count tracks how many skbs has been sent for the current queue before going to the next queue */
	// static u32;
	int i = 0, qid = last_q;
	int lower_bound = 0;
	int num_queue = 0;
	if(prio_class) {
		lower_bound = nd_params.lat_channel_idx;
		num_queue = nd_params.num_lat_channels;
	} else {
		lower_bound = nd_params.thpt_channel_idx;
		num_queue =  nd_params.num_thpt_channels;
	}
	// if(nd_params.nd_num_queue == 1)
	// 	i = 0;
	/* advance to the next queue */
	if(cur_count >= queues[last_q].compact_low_thre) {
		last_q = (last_q + 1) % num_queue + lower_bound;
		// cur_count = 0;
	}
	for (; i < num_queue; i++) {
		/* select queue */
		qid = (last_q + i) % num_queue + lower_bound;
		queue =  &queues[qid];
		// WARN_ON(cur_count >= queue->compact_low_thre);

		if(atomic_read(&queue->cur_queue_size) 
			>= queue->queue_size) {
			/* update the count */
			// cur_count = 0;
			continue;
		} else {
			// cur_count++;
		}
		// atomic_add(1, &queue->cur_queue_size);
		last_q = qid;
		return qid;
	}
	if(avoid_check) {
		qid = (1 + last_q) % num_queue + lower_bound;
		queue =  &queues[qid];
		// atomic_add(1, &queue->cur_queue_size);
		last_q = qid;
		return last_q;
	}
	return -1;
}

/* round-robin; will not select the previous one except if there is only one channel. */
int nd_conn_sche_low_lat(void) {
	return  raw_smp_processor_id() / 4 + nd_params.lat_channel_idx;
}

/* round-robin; will not select the previous one except if there is only one channel. */
int nd_conn_sche_src_port(struct nd_conn_queue *queues, int src_port, bool avoid_check, int pri_class) {
        struct nd_conn_queue *queue;
        int qid;
        if(pri_class)
                qid = src_port % nd_params.num_lat_channels + nd_params.lat_channel_idx;
        else
                qid = src_port % nd_params.num_thpt_channels + nd_params.thpt_channel_idx;
        queue = &queues[qid];
        if(atomic_read(&queue->cur_queue_size)
                >= queue->queue_size && !avoid_check) {
                /* update the count */
                // cur_count = 0;
                return -1;
        } else {
                return qid;
                // cur_count++;
        }
        return -1;
}

/* stick on one queue if the queue size is below than threshold; */
// int nd_conn_sche_compact(bool avoid_check) {
// 	struct nd_conn_queue *queue;
// 	static u32 last_q = 0;
// 	int i = 1, qid;
// 	/* try low threshold first */
// 	for (i = 0; i < nd_params.nd_num_queue; i++) {

// 		qid = (i) % (nd_params.nd_num_queue);
// 		queue =  &nd_ctrl->queues[qid];
// 		if(atomic_fetch_add_unless(&queue->cur_queue_size, 1, queue->compact_low_thre) 
// 			== queue->compact_low_thre) {
// 			continue;
// 		}
// 		WARN_ON(atomic_read(&queue->cur_queue_size) > queue->compact_low_thre);
// 		// if(qid == 1){
// 		// 	printk("qid 1 is being used\n");
// 		// }
// 		last_q = qid;
// 		return last_q;
// 	}
// 	/* then try high threshold*/
// 	// for (i = 0; i < nd_params.nd_num_queue; i++) {

// 	// 	qid = (i) % (nd_params.nd_num_queue);
// 	// 	queue =  &nd_ctrl->queues[qid];
// 	// 	if(atomic_fetch_add_unless(&queue->cur_queue_size, 1, queue->compact_high_thre) 
// 	// 		== queue->compact_high_thre) {
// 	// 		continue;
// 	// 	}
// 	// 	last_q = qid;
// 	// 	return last_q;
// 	// }
// 	/* when all queues become full and avoid check is true */
// 	/* do rr */
// 	if(avoid_check) {
// 		qid = (1 + last_q) % (nd_params.nd_num_queue);
// 		queue =  &nd_ctrl->queues[qid];
// 		atomic_add(1, &queue->cur_queue_size);
// 		last_q = qid;
// 		return last_q;
// 	}
// 	return -1;
// }

/* find nd_ctrl based on dest ip address */
void* nd_conn_find_nd_ctrl(__be32 dst_addr) {
	struct nd_conn_ctrl *nd_ctrl;
	/*find the nd ctrl */
	hash_for_each_possible(nd_conn_table, nd_ctrl, hlist, dst_addr) {
		return nd_ctrl;
		break;
	} 
	return NULL;
}

bool nd_conn_queue_request(struct nd_conn_request *req, struct nd_sock *nsk,
		bool sync, bool avoid_check, bool last)
{
    struct inet_sock *inet = inet_sk((struct sock*)nsk);
	struct nd_conn_queue *queue = req->queue, *last_q;
	struct nd_conn_ctrl *nd_ctrl = nsk->nd_ctrl;
	// static u32 queue_id = 0;
	bool empty;
	// bool push = false;
	int ret;
	int qid = 0;
	WARN_ON(nsk == NULL);
	if(queue == NULL) { 
		/* hard code for now */
		// queue_id = (smp_processor_id() - 16) / 4;
		// if(req->prio_class)
		// 	qid = nd_conn_sche_low_lat();
		// else
	//		qid = nd_conn_sche_rr(nsk->sender.con_queue_id, nsk->sender.con_accumu_count, req->prio_class, avoid_check);
		if(nsk->sche_policy == SCHE_SRC_PORT)
			qid = nd_conn_sche_src_port(nd_ctrl->queues, ntohs(inet->inet_sport), avoid_check, req->prio_class);
		else if(nsk->sche_policy == SCHE_RR)
			qid = nd_conn_sche_rr(nd_ctrl->queues, nsk->sender.con_queue_id, nsk->sender.con_accumu_count, req->prio_class, avoid_check);
		if(qid < 0) {
			/* wake up previous queue */
			if(nsk->sender.con_queue_id != - 1) {
				last_q =  &nd_ctrl->queues[nsk->sender.con_queue_id];
				if(nd_conn_queue_is_lat(last_q)) {
					queue_work_on(last_q->io_cpu, nd_conn_wq_lat, &last_q->io_work);
				}else {
					queue_work_on(last_q->io_cpu, nd_conn_wq, &last_q->io_work);
				}					
			}
			return false;
		}
		req->queue = &nd_ctrl->queues[qid];
		// req->queue =  &nd_ctrl->queues[6];
		queue = req->queue;
		atomic_add(1, &queue->cur_queue_size);
		/* update nsk state */
		if(nsk->sche_policy == SCHE_RR) {
			if(qid == nsk->sender.con_queue_id)
				nsk->sender.con_accumu_count += 1;
			else {
				/* wake up previous queue */
				// printk("wake up previous channel:%d\n", nsk->sender.con_queue_id);
				if(nsk->sender.con_queue_id != - 1) {
					last_q =  &nd_ctrl->queues[nsk->sender.con_queue_id];
					if(nd_conn_queue_is_lat(last_q)) {
						queue_work_on(last_q->io_cpu, nd_conn_wq_lat, &last_q->io_work);
					}else {
						queue_work_on(last_q->io_cpu, nd_conn_wq, &last_q->io_work);
					}					
				}
				/* reinitalize the sk state */
				nsk->sender.con_accumu_count = 1;
			}
		}
		nsk->sender.con_queue_id = qid;
		// queue_id += 1;
	} else {
		atomic_add(1, &queue->cur_queue_size);
	}
	// bytes_sent[qid] += 1;
	WARN_ON(req->queue == NULL);
	// if(!avoid_check){
	// 	if(atomic_fetch_add_unless(&queue->cur_queue_size, 1, queue->queue_size) 
	// 	== queue->queue_size)
	// 		return false;
	// }
	empty = llist_add(&req->lentry, &queue->req_list) &&
		list_empty(&queue->send_list) && !queue->request;

	/*
	 * if we're the first on the send_list and we can try to send
	 * directly, otherwise queue io_work. Also, only do that if we
	 * are on the same cpu, so we don't introduce contention.
	 */
	if (queue->io_cpu == smp_processor_id() &&
	    sync && empty && mutex_trylock(&queue->send_mutex)) {
		// queue->more_requests = !last;
		ret = nd_conn_try_send(queue);
		// if(ret == -EAGAIN)
		// 	queue->more_requests = false;
		mutex_unlock(&queue->send_mutex);
	} else if(last){
		/* data packets always go here */
		// printk("wake up last channel:%d\n", nsk->sender.con_queue_id);
		if(nd_conn_queue_is_lat(queue)) {
			queue_work_on(queue->io_cpu, nd_conn_wq_lat, &queue->io_work);
		}else {
			queue_work_on(queue->io_cpu, nd_conn_wq, &queue->io_work);
		}
	}
	return true;
}

void nd_conn_teardown_ctrl(struct nd_conn_ctrl *ctrl, bool shutdown)
{
	nd_conn_teardown_io_queues(ctrl, shutdown);
}

void nd_conn_delete_ctrl(struct nd_conn_ctrl *ctrl)
{
	nd_conn_teardown_ctrl(ctrl, true);
	hash_del(&ctrl->hlist);
	// flush_workqueue(ctrl->sock_wait_wq);
	// destroy_workqueue(ctrl->sock_wait_wq);
    /* free option here */
	kfree(ctrl->queues);
    kfree(ctrl->opts);
	kfree(ctrl);
}

void nd_conn_teardown_io_queues(struct nd_conn_ctrl *ctrl,
		bool remove)
{
	mutex_lock(&ctrl->teardown_lock);
    // might need to change later
	// if (ctrl->queue_count <= 1)
	// 	goto out;
	nd_conn_stop_io_queues(ctrl);
	nd_conn_destroy_io_queues(ctrl, remove);
	mutex_unlock(&ctrl->teardown_lock);
}

unsigned int nd_conn_nr_io_queues(struct nd_conn_ctrl *ctrl)
{
	unsigned int nr_io_queues;

	nr_io_queues = min(ctrl->opts->nr_io_queues, num_online_cpus());
	// nr_io_queues += min(ctrl->opts->nr_write_queues, num_online_cpus());
	// nr_io_queues += min(ctrl->opts->nr_poll_queues, num_online_cpus());

	return nr_io_queues;
}

int nd_conn_alloc_io_queues(struct nd_conn_ctrl *ctrl)
{
	unsigned int nr_io_queues;
	// int ret;
	nr_io_queues = nd_conn_nr_io_queues(ctrl);
	ctrl->queue_count = nr_io_queues;
	return __nd_conn_alloc_io_queues(ctrl);
}

int __nd_conn_alloc_io_queues(struct nd_conn_ctrl *ctrl)
{
	int i, ret;

	for (i = 0; i < ctrl->queue_count; i++) {
		ret = nd_conn_alloc_queue(ctrl, i);
		if (ret)
			goto out_free_queues;
	}

	return 0;

out_free_queues:
	for (i--; i >= 0; i--)
		nd_conn_free_queue(ctrl, i);

	return ret;
}

void nd_conn_destroy_io_queues(struct nd_conn_ctrl *ctrl, bool remove)
{
	nd_conn_stop_io_queues(ctrl);
	nd_conn_free_io_queues(ctrl);
}

int nd_conn_configure_io_queues(struct nd_conn_ctrl *ctrl, bool new)
{
	int ret;

	ret = nd_conn_alloc_io_queues(ctrl);
	if (ret)
		return ret;
	return 0;
}

void nd_conn_process_req_list(struct nd_conn_queue *queue)
{
	struct nd_conn_request *req;
	struct llist_node *node;

	for (node = llist_del_all(&queue->req_list); node; node = node->next) {
		req = llist_entry(node, struct nd_conn_request, lentry);
		list_add(&req->entry, &queue->send_list);
	}
}

static inline struct nd_conn_request *
nd_conn_fetch_request(struct nd_conn_queue *queue)
{
	struct nd_conn_request *req;

	req = list_first_entry_or_null(&queue->send_list,
			struct nd_conn_request, entry);
	if (!req) {
		nd_conn_process_req_list(queue);
		req = list_first_entry_or_null(&queue->send_list,
				struct nd_conn_request, entry);
		if (unlikely(!req))
			return NULL;
	}

	list_del(&req->entry);
	return req;
}

int nd_conn_try_send_cmd_pdu(struct nd_conn_request *req)
{
	struct nd_conn_queue *queue = req->queue;
	struct ndhdr *hdr = req->hdr;
	bool inline_data = nd_conn_has_inline_data(req);
	/* it should be non-block */
	int flags = MSG_DONTWAIT | (inline_data ? MSG_MORE : MSG_EOR);
	int len = sizeof(*hdr) - req->offset;
	int ret;

	// printk("nd_conn_try_send_cmd_pdu: type:%d\n", hdr->type);
	ret = kernel_sendpage(queue->sock, virt_to_page(hdr),
			offset_in_page(hdr) + req->offset, len,  flags);
	
	// pr_info("inline_data:%d\n", inline_data);
	// pr_info("send ack grant seq:%u\n", htonl(hdr->grant_seq));
	// pr_info("ret:%d\n", ret);
	// printk("pdu->source:%d\n", ntohs(hdr->source));
	// printk("pdu->dest:%d\n", ntohs(hdr->dest));
	// printk("ret :%d\n", ret);

	if (unlikely(ret <= 0)) {
		return ret;
	}
	len -= ret;
	if (!len) {
		if(inline_data) {
			req->state = ND_CONN_SEND_DATA;
			/* initialize the sending state */
		} else {
			req->state = ND_CONN_PDU_DONE;
			// nd_conn_done_send_req(queue);
		}
		return 1;
	}
	req->offset += ret;
	return -EAGAIN;
}
extern ktime_t start_time;
int nd_conn_try_send_data_pdu(struct nd_conn_request *req)
{
	struct nd_conn_queue *queue = req->queue;
	struct sk_buff *skb = req->skb;
	// unsigned int sent = req->sent;
	int ret = 0;
 	skb_frag_t *frag;
	// printk("skb_shinfo(skb)->nr_frags:%d\n", skb_shinfo(skb)->nr_frags);
	while(true) {
		int flags = MSG_DONTWAIT;
		unsigned short frag_offset = req->frag_offset, 
			fragidx = req->fragidx;
		frag = &skb_shinfo(skb)->frags[fragidx];
		/* this part should be handled in the future */
		while (WARN_ON(!skb_frag_size(frag))) {
			fragidx += 1;
			if (fragidx == skb_shinfo(skb)->nr_frags) {
				req->state = ND_CONN_PDU_DONE;
				return 1;
			}
			frag = &skb_shinfo(skb)->frags[fragidx];
		}
		if(fragidx == skb_shinfo(skb)->nr_frags - 1 && atomic_read(&queue->cur_queue_size) == 1) {
			flags |= MSG_EOR;
		} else {
			flags |= MSG_MORE;
		}
		// if(queue->qid == 0)
		// 	printk("time diff: %lld\n", ktime_to_us(ktime_sub(ktime_get(), start_time)));

		ret = kernel_sendpage(queue->sock,
						skb_frag_page(frag),
						skb_frag_off(frag) + frag_offset,
						skb_frag_size(frag) - frag_offset,
						flags);
		if(ret <= 0) {
			return ret;
		}
		// printk("send data bytes:%d\n", ret);
		frag_offset += ret;
		if(frag_offset == skb_frag_size(frag)) {
			if(fragidx == skb_shinfo(skb)->nr_frags - 1) {
				/* sending is done */
				// printk("ND_CONN_PDU_DONE\n");
				req->state = ND_CONN_PDU_DONE;
				return 1;
			} else {
				/* move to the next frag */
				// printk("move to the next frag\n");
				req->frag_offset = 0;
				req->fragidx += 1;
			}
		} else {
			/* increment the offset */
			req->frag_offset = frag_offset;
		}
	}
	return -EAGAIN;
}

int nd_conn_try_send(struct nd_conn_queue *queue)
{
	struct nd_conn_request *req;
	int ret = 1;

	if (!queue->request) {
		queue->request = nd_conn_fetch_request(queue);
		if (!queue->request)
			return 0;
	}
	req = queue->request;
	if (req->state == ND_CONN_SEND_CMD_PDU) {
		ret = nd_conn_try_send_cmd_pdu(req);
		if (ret <= 0)
			goto done;
		if (req->state == ND_CONN_PDU_DONE)
			goto clean;
	}

	
	if (req->state == ND_CONN_SEND_DATA) {
		// printk("send data pdu\n");
		ret = nd_conn_try_send_data_pdu(req);
		// if(max_queue_length < atomic_read(&queue->cur_queue_size))
		// 	max_queue_length = atomic_read(&queue->cur_queue_size);
		if (ret <= 0)
			goto done;
		// if (ret == 1) {
		// 	atomic_dec(&queue->cur_queue_size);
		// }
	}

	// if (req->state == NVME_TCP_SEND_DATA) {
	// 	ret = nvme_tcp_try_send_data(req);
	// 	if (ret <= 0)
	// 		goto done;
	// }
clean:
	// printk("queue cpu:%d  size %d\n", queue->io_cpu, atomic_read(&queue->cur_queue_size));
	atomic_dec(&queue->cur_queue_size);
	nd_conn_done_send_req(queue);
	// if (req->state == NVME_TCP_SEND_DDGST)
	// 	ret = nvme_tcp_try_send_ddgst(req);
done:
	if (ret == -EAGAIN) {
		ret = 0;
	} else if (ret < 0) {
		pr_err("failed to send request %d\n", ret);
		// if (ret != -EPIPE && ret != -ECONNRESET)
		// 	nvme_tcp_fail_request(queue->request);
		nd_conn_done_send_req(queue);
	}
	return ret;
}
uint32_t total_time = 0;

void nd_conn_io_work(struct work_struct *w)
{
	struct nd_conn_queue *queue =
		container_of(w, struct nd_conn_queue, io_work);
	unsigned long deadline = jiffies + msecs_to_jiffies(1);
	bool pending;
	// int bufsize;
	// int optlen = sizeof(bufsize);
	// pr_info("queue size:%u\n", atomic_read(&queue->cur_queue_size));
	total_time += 1;
	do {
		int result;
		pending = false;
		mutex_lock(&queue->send_mutex);
		result = nd_conn_try_send(queue);
		mutex_unlock(&queue->send_mutex);
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
	// ret = kernel_getsockopt(queue->sock, SOL_SOCKET, SO_SNDBUF,
	// 	(char *)&bufsize, &optlen);
	// pr_info("ret value:%d\n", ret);
	// pr_info("buffer size receive:%d\n", bufsize);
	if(pending) {
		if(nd_conn_queue_is_lat(queue)) {
			queue_work_on(queue->io_cpu, nd_conn_wq_lat, &queue->io_work);
		}else {
			queue_work_on(queue->io_cpu, nd_conn_wq, &queue->io_work);
		}
	}
	// ret = queue_work_on(queue->io_cpu, nd_conn_wq, &queue->io_work);
	/* To Do: only wake up all socks if there is available space */
	if(atomic_read(&queue->cur_queue_size) < queue->queue_size)
			nd_conn_wake_up_all_socks(queue);
}

/* assume hold socket lock */
void nd_conn_add_sleep_sock(struct nd_conn_ctrl *ctrl, struct nd_sock *nsk) {
	uint32_t qid = 0;
	struct sock *sk = (struct sock*)(nsk);
	struct inet_sock *inet = inet_sk(sk);
	bool pri_class = sk->sk_priority == 0? 0 : 1;
	struct nd_conn_queue *queue;
	int src_port = ntohs(inet->inet_sport);
	if(nsk->sche_policy == SCHE_SRC_PORT) {
		if(pri_class)
			qid = src_port % nd_params.num_lat_channels + nd_params.lat_channel_idx;
		else
			qid = src_port % nd_params.num_thpt_channels + nd_params.thpt_channel_idx;
	} else if(nsk->sche_policy == SCHE_RR){
		/* for now pick the current sending queue */
		qid = nsk->sender.con_queue_id;
	}
	queue = &ctrl->queues[qid];
	spin_lock_bh(&queue->sock_wait_lock);
	if(nsk->sender.wait_on_nd_conns) {
		spin_unlock_bh(&queue->sock_wait_lock);
		goto queue_work;
	}
	nsk->sender.wait_cpu = raw_smp_processor_id();
	nsk->sender.wait_on_nd_conns = true;
	/* might have to add ref count later */
	nsk->sender.wait_queue = queue;
	list_add_tail(&nsk->tx_wait_list, &queue->sock_wait_list);
	spin_unlock_bh(&queue->sock_wait_lock);
	/* wake up corresponding queue */
queue_work:
	if(nd_conn_queue_is_lat(queue)) {
		queue_work_on(queue->io_cpu, nd_conn_wq_lat, &queue->io_work);
	}else {
		queue_work_on(queue->io_cpu, nd_conn_wq, &queue->io_work);
	}
}

// void nd_conn_add_sleep_sock(struct nd_conn_ctrl *ctrl, struct nd_sock* nsk) {
// 	uint32_t i, index;
// 	spin_lock_bh(&ctrl->sock_wait_lock);
// 	// printk("add sleep sock\n");
// 	if(nsk->sender.wait_on_nd_conns)
// 		goto queue_work;
// 	nsk->sender.wait_cpu = raw_smp_processor_id();
// 	nsk->sender.wait_on_nd_conns = true;
// 	list_add_tail(&nsk->tx_wait_list, &ctrl->sock_wait_list);
// queue_work:
// 	spin_unlock_bh(&ctrl->sock_wait_lock);
// 	for(i = 0; i < nd_params.num_thpt_channels; i++) {
// 		index = i + nd_params.thpt_channel_idx;
// 		if(nd_conn_queue_is_lat(&ctrl->queues[index])) {
// 			queue_work_on(ctrl->queues[index].io_cpu, nd_conn_wq_lat, &ctrl->queues[index].io_work);
// 		}else {
// 			queue_work_on(ctrl->queues[index].io_cpu, nd_conn_wq, &ctrl->queues[index].io_work);
// 		}
// 		// queue_work_on(ctrl->queues[i].io_cpu, nd_conn_wq, &ctrl->queues[i].io_work);
// 	}
// }

void nd_conn_remove_sleep_sock(struct nd_conn_queue *queue, struct nd_sock *nsk) {
	if(nsk->sender.wait_on_nd_conns) {
		spin_lock_bh(&queue->sock_wait_lock);
		list_del_init(&nsk->tx_wait_list);
		nsk->sender.wait_on_nd_conns = false;
		nsk->sender.wait_queue = NULL;
		spin_unlock_bh(&queue->sock_wait_lock);
	}
}

void nd_conn_wake_up_all_socks(struct nd_conn_queue *queue) {
	struct nd_sock *nsk; 
	spin_lock_bh(&queue->sock_wait_lock);
	list_for_each_entry(nsk, &queue->sock_wait_list, tx_wait_list) {
		WARN_ON(!nsk->sender.wait_on_nd_conns);
		queue_work_on(nsk->sender.wait_cpu, sock_wait_wq, &nsk->tx_work);
		nsk->sender.wait_on_nd_conns = false;
		nsk->sender.wait_queue = NULL;
	}
	INIT_LIST_HEAD(&queue->sock_wait_list);
	spin_unlock_bh(&queue->sock_wait_lock);
}

int nd_conn_alloc_queue(struct nd_conn_ctrl *ctrl,
		int qid)
{
	// struct nvme_tcp_ctrl *ctrl = to_tcp_ctrl(nctrl);
	struct nd_conn_queue *queue = &ctrl->queues[qid];
	struct linger sol = { .l_onoff = 1, .l_linger = 0 };
	int ret, opt, n;
	// int bufsize = 1000000;
	// int optlen = sizeof(bufsize);
	queue->ctrl = ctrl;
    init_llist_head(&queue->req_list);
	INIT_LIST_HEAD(&queue->send_list);
	/* init socket wait list */
	INIT_LIST_HEAD(&queue->sock_wait_list);
	spin_lock_init(&queue->sock_wait_lock);

	// spin_lock_init(&queue->lock);
    mutex_init(&queue->send_mutex);
	INIT_WORK(&queue->io_work, nd_conn_io_work);
	queue->queue_size = ctrl->opts->queue_size;
	queue->compact_low_thre = ctrl->opts->compact_low_thre;
	queue->compact_high_thre = ctrl->opts->compact_high_thre;
	atomic_set(&queue->cur_queue_size, 0);


	if (qid >= ctrl->queue_count / 2) {
		/* latency-sensitive channel */
		queue->prio_class = 1;
	} else
		/* throughput-bound channel */
		queue->prio_class = 0;
	// if (qid > 0)
	// 	queue->cmnd_capsule_len = nctrl->ioccsz * 16;
	// else
	// 	queue->cmnd_capsule_len = sizeof(struct nvme_command) +
	// 					NVME_TCP_ADMIN_CCSZ;

	ret = sock_create(ctrl->addr.ss_family, SOCK_STREAM,
			IPPROTO_TCP, &queue->sock);
	if (ret) {
		pr_err("failed to create socket: %d\n", ret);
		return ret;
	}

	/* Single syn retry */
	opt = 1;
	ret = kernel_setsockopt(queue->sock, IPPROTO_TCP, TCP_SYNCNT,
			(char *)&opt, sizeof(opt));
	if (ret) {
		pr_err("failed to set TCP_SYNCNT sock opt %d\n", ret);
		goto err_sock;
	}
	// tcp_sock_set_syncnt(queue->sock->sk, 1);
	/* Set TCP no delay */
	opt = 1;
	ret = kernel_setsockopt(queue->sock, IPPROTO_TCP,
			TCP_NODELAY, (char *)&opt, sizeof(opt));
	if (ret) {
		pr_err("failed to set TCP_NODELAY sock opt %d\n", ret);
		goto err_sock;
	}
	// tcp_sock_set_nodelay(queue->sock->sk);
	/*
	 * Cleanup whatever is sitting in the TCP transmit queue on socket
	 * close. This is done to prevent stale data from being sent should
	 * the network connection be restored before TCP times out.
	 */
	ret = kernel_setsockopt(queue->sock, SOL_SOCKET, SO_LINGER,
			(char *)&sol, sizeof(sol));
	if (ret) {
		pr_err("failed to set SO_LINGER sock opt %d\n", ret);
		goto err_sock;
	}
	// sock_no_linger(queue->sock->sk);
	/* Set socket type of service */
	// if (ctrl->opts->tos >= 0) {
	// 	opt = ctrl->opts->tos;
	// 	ret = kernel_setsockopt(queue->sock, SOL_IP, IP_TOS,
	// 			(char *)&opt, sizeof(opt));
	// 	if (ret) {
	// 		pr_err("failed to set IP_TOS sock opt %d\n", ret);
	// 		goto err_sock;
	// 	}
	// }
	// if (so_priority > 0)
	// 	sock_set_priority(queue->sock->sk, so_priority);
	// if (ctrl->opts->tos >= 0)
	// 	ip_sock_set_tos(queue->sock->sk, ctrl->opts->tos);
    // io cpu might be need to be changed later
	// ret = kernel_getsockopt(queue->sock, SOL_SOCKET, SO_SNDBUF,
	// 	(char *)&bufsize, &optlen);
	// pr_info("ret value:%d\n", ret);
	// pr_info("buffer size sender:%d\n", bufsize);
	// bufsize = 4000000;
	// ret = kernel_setsockopt(queue->sock, SOL_SOCKET, SO_SNDBUF,
	// 		(char *)&bufsize, sizeof(bufsize));
	queue->sock->sk->sk_allocation = GFP_ATOMIC;
	if (!qid)
		n = 0;
	else
		n = (qid - 1) % num_online_cpus();
	// queue->io_cpu = cpumask_next_wrap(n - 1, cpu_online_mask, -1, false);
	/* mod 28 is hard code for now. */
	queue->io_cpu = (4 * qid) % 32;
	// queue->io_cpu = 0;
	queue->qid = qid;
	// printk("queue id:%d\n", queue->io_cpu);
	queue->request = NULL;
	// queue->data_remaining = 0;
	// queue->ddgst_remaining = 0;
	// queue->pdu_remaining = 0;
	// queue->pdu_offset = 0;
	sk_set_memalloc(queue->sock->sk);

	// if (nctrl->opts->mask & NVMF_OPT_HOST_TRADDR) {
		ret = kernel_bind(queue->sock, (struct sockaddr *)&ctrl->src_addr,
			sizeof(ctrl->src_addr));
		if (ret) {
			pr_err("failed to bind queue %d socket %d\n",qid, ret);
			goto err_sock;
		}
	// }

	// queue->hdr_digest = nctrl->opts->hdr_digest;
	// queue->data_digest = nctrl->opts->data_digest;
	// if (queue->hdr_digest || queue->data_digest) {
	// 	ret = nvme_tcp_alloc_crypto(queue);
	// 	if (ret) {
	// 		dev_err(nctrl->device,
	// 			"failed to allocate queue %d crypto\n", qid);
	// 		goto err_sock;
	// 	}
	// }

	// rcv_pdu_size = sizeof(struct nvme_tcp_rsp_pdu) +
	// 		nvme_tcp_hdgst_len(queue);
	// queue->pdu = kmalloc(rcv_pdu_size, GFP_KERNEL);
	// if (!queue->pdu) {
	// 	ret = -ENOMEM;
	// 	goto err_crypto;
	// }

	// dev_dbg(nctrl->device, "connecting queue %d\n",
	// 		nvme_tcp_queue_id(queue));

	ret = kernel_connect(queue->sock, (struct sockaddr *)&ctrl->addr,
		sizeof(ctrl->addr), 0);
	if (ret) {
		pr_err("failed to connect socket: %d\n", ret);
		goto err_rcv_pdu;
	}
    // this part needed to be handled later
	// ret = nvme_tcp_init_connection(queue);
	if (ret)
		goto err_init_connect;

	queue->rd_enabled = true;
	set_bit(ND_CONN_Q_ALLOCATED, &queue->flags);
	// nvme_tcp_init_recv_ctx(queue);

	write_lock_bh(&queue->sock->sk->sk_callback_lock);
	queue->sock->sk->sk_user_data = queue;
	queue->state_change = queue->sock->sk->sk_state_change;
	queue->data_ready = queue->sock->sk->sk_data_ready;
	queue->write_space = queue->sock->sk->sk_write_space;
	queue->sock->sk->sk_data_ready = nd_conn_data_ready;
	queue->sock->sk->sk_state_change = nd_conn_state_change;
	queue->sock->sk->sk_write_space = nd_conn_write_space;
#ifdef CONFIG_NET_RX_BUSY_POLL
	queue->sock->sk->sk_ll_usec = 1;
#endif
	write_unlock_bh(&queue->sock->sk->sk_callback_lock);

	return 0;

err_init_connect:
	kernel_sock_shutdown(queue->sock, SHUT_RDWR);
err_rcv_pdu:
	// kfree(queue->pdu);
// err_crypto:
// 	if (queue->hdr_digest || queue->data_digest)
// 		nvme_tcp_free_crypto(queue);
err_sock:
	sock_release(queue->sock);
	queue->sock = NULL;
	return ret;
}

// int nd_conn_alloc_admin_queue(struct nd_conn_ctrl *ctrl)
// {
// 	int ret;

// 	ret = nd_conn_alloc_queue(ctrl, 0);
// 	if (ret)
// 		return ret;

// 	// ret = nvme_tcp_alloc_async_req(to_tcp_ctrl(ctrl));
// 	if (ret)
// 		goto out_free_queue;

// 	return 0;

// out_free_queue:
// 	nd_conn_free_queue(ctrl, 0);
// 	return ret;
// }

int nd_conn_setup_ctrl(struct nd_conn_ctrl *ctrl, bool new)
{
	int ret;
	ret = nd_conn_configure_io_queues(ctrl, new);
	if (ret)
		goto destroy_admin;
	return 0;
destroy_admin:
	nd_conn_stop_queue(ctrl, 0);
	return ret;
}


struct nd_conn_ctrl *nd_conn_create_ctrl(struct nd_conn_ctrl_options *opts)
{
	struct nd_conn_ctrl *ctrl;
	struct sockaddr_in *target_addr;
	int ret;

	ctrl = kzalloc(sizeof(*ctrl), GFP_KERNEL);
	if (!ctrl) {
		kfree(opts);
		return ERR_PTR(-ENOMEM);
	}

	// INIT_LIST_HEAD(&ctrl->list);
	ctrl->opts = opts;
	ctrl->queue_count = opts->nr_io_queues + opts->nr_write_queues +
				opts->nr_poll_queues;
	// ctrl->sqsize = opts->queue_size - 1;
	// ctrl->ctrl.kato = opts->kato;
    // pr_info("queue count: %u\n", ctrl->queue_count);
	// INIT_DELAYED_WORK(&ctrl->connect_work,
	// 		nvme_tcp_reconnect_ctrl_work);
	// INIT_WORK(&ctrl->err_work, nd_conn_error_recovery_work);
	// INIT_WORK(&ctrl->ctrl.reset_work, nvme_reset_ctrl_work);
    mutex_init(&ctrl->teardown_lock);

	// if (!(opts->mask & NVMF_OPT_TRSVCID)) {
	// 	opts->trsvcid =
	// 		kstrdup(__stringify(NVME_TCP_DISC_PORT), GFP_KERNEL);
	// 	if (!opts->trsvcid) {
	// 		ret = -ENOMEM;
	// 		goto out_free_ctrl;
	// 	}
	// 	opts->mask |= NVMF_OPT_TRSVCID;
	// }

	ret = inet_pton_with_scope(&init_net, AF_UNSPEC,
			opts->traddr, opts->trsvcid, &ctrl->addr);
	if (ret) {
		pr_err("malformed address passed: %s:%s\n",
			opts->traddr, opts->trsvcid);
		goto out_free_ctrl;
	}
	target_addr = (struct sockaddr_in *)(&ctrl->addr);

	ret = inet_pton_with_scope(&init_net, AF_UNSPEC,
		opts->host_traddr, NULL, &ctrl->src_addr);
	if (ret) {
		pr_err("malformed src address passed: %s\n",
				opts->host_traddr);
		goto out_free_ctrl;
	}
	ctrl->queues = kcalloc(ctrl->queue_count, sizeof(*ctrl->queues),
				GFP_KERNEL);
	if (!ctrl->queues) {
		ret = -ENOMEM;
		goto out_free_ctrl;
	}
	ret = nd_conn_setup_ctrl(ctrl, true);
	if (ret)
		goto out_uninit_ctrl;
    pr_info("create ctrl sucessfully\n");
	mutex_lock(&nd_conn_ctrl_mutex);
	// list_add_tail(&ctrl->list, &nd_conn_ctrl_list);
	hash_add(nd_conn_table, &ctrl->hlist, target_addr->sin_addr.s_addr);
	mutex_unlock(&nd_conn_ctrl_mutex);

	return ctrl;

out_uninit_ctrl:
	/* To Do: handle it corrrectly */
	WARN_ON(true);
	// nvme_uninit_ctrl(&ctrl->ctrl);
	// nvme_put_ctrl(&ctrl->ctrl);
	if (ret > 0)
		ret = -EIO;
	// return ERR_PTR(ret);
// out_kfree_queues:
	kfree(ctrl->opts);
	kfree(ctrl->queues);
out_free_ctrl:
	kfree(ctrl);
	return ERR_PTR(ret);
}

int nd_conn_init_module(void)
{
	struct nd_conn_ctrl_options* opts;
	int i;
	nd_conn_wq = alloc_workqueue("nd_conn_wq",
			WQ_MEM_RECLAIM, 0);

	if (!nd_conn_wq)
		return -ENOMEM;
	nd_conn_wq_lat = alloc_workqueue("nd_conn_wq_lat",
			WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
	if(!nd_conn_wq_lat)
		return -ENOMEM;
	sock_wait_wq = alloc_workqueue("sock_wait_wq",
			WQ_MEM_RECLAIM, 0);
	if(!sock_wait_wq)
		return -ENOMEM;		
    // pr_info("HCTX_MAX_TYPES: %d\n", HCTX_MAX_TYPES);
	/* hash table init */
	hash_init(nd_conn_table);
	
	for (i = 0; i < nd_params.num_remote_hosts; i++) {
	    /* initialiize the option */
		opts = kmalloc(sizeof(*opts), GFP_KERNEL);
		opts->nr_io_queues = nd_params.total_channels;
		opts->nr_write_queues = 0;
		opts->nr_poll_queues = 0;
		/* target address */
		opts->traddr = nd_params.remote_ips[i];
		opts->trsvcid = "9000";
		/* src address */
		opts->host_traddr = nd_params.local_ip;
		// opts->host_port = "10000";

		opts->queue_size = 32;
		opts->compact_high_thre = 256;
		opts->compact_low_thre = 6;
		opts->tos = 0;
		pr_info("create the ctrl \n");
		nd_conn_create_ctrl(opts);
	}

	// nvmf_register_transport(&nvme_tcp_transport);
	return 0;
}

void nd_conn_cleanup_module(void)
{
	struct nd_conn_ctrl *ctrl;
	struct hlist_node *tmp;
	int i;
	// nvmf_unregister_transport(&nvme_tcp_transport);

	mutex_lock(&nd_conn_ctrl_mutex);
	hash_for_each_safe(nd_conn_table, i, tmp, ctrl, hlist)
		nd_conn_delete_ctrl(ctrl);
	mutex_unlock(&nd_conn_ctrl_mutex);
	// flush_workqueue(nvme_delete_wq);

	destroy_workqueue(sock_wait_wq);
	destroy_workqueue(nd_conn_wq);
	destroy_workqueue(nd_conn_wq_lat);
}
