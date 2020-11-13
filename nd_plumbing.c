#include <linux/skbuff.h>
#include <net/protocol.h>
#include <net/inet_common.h>

//#include "include/net/nd.h"
//#include "nd_impl.h"
#include <linux/socket.h>
#include <net/sock.h>
#include <net/udp.h>
#include "nd_impl.h"
#include "nd_target.h"
#include "nd_host.h"
#include "nd_unittest.h"
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Qizhe");
MODULE_DESCRIPTION("ND transport protocol");
MODULE_VERSION("0.01");

#include "net_nd.h"


/* True means that the ND module is in the process of unloading itself,
 * so everyone should clean up.
 */

static bool exiting = false;
int sysctl_nd_rmem_min __read_mostly;
int sysctl_nd_wmem_min __read_mostly;

/* ND's protocol number within the IP protocol space (this is not an
 * officially allocated slot).
 */

// struct test_element{
//     struct list_head node;
//     int value;
// };

// bool test_compare(const struct list_head* node1, const struct list_head* node2) {
//     struct test_element *e1, *e2;
//     e1 = list_entry(node1, struct test_element, node);
//     e2 = list_entry(node2, struct test_element, node);
//     if(e1->value > e2->value)
//         return true;
//     return false;

// }
// #define IPPROTO_VIRTUAL_SOCK 200

const struct proto_ops nd_dgram_ops = {
    .family        = PF_INET,
    .owner         = THIS_MODULE,
    .release       = inet_release,
    .bind          = inet_bind,
    .connect       = inet_dgram_connect,
    .socketpair    = sock_no_socketpair,
    .accept        = inet_accept,
    .getname       = inet_getname,
    .poll          = udp_poll,
    .ioctl         = inet_ioctl,
    .gettstamp     = sock_gettstamp,
    .listen        = nd_listen,
    .shutdown      = inet_shutdown,
    .setsockopt    = sock_common_setsockopt,
    .getsockopt    = sock_common_getsockopt,
    .sendmsg       = inet_sendmsg,
    .recvmsg       = inet_recvmsg,
    .mmap          = sock_no_mmap,
    .sendpage      = inet_sendpage,
    .set_peek_off      = sk_set_peek_off,
// #ifdef CONFIG_COMPAT
//     .compat_setsockopt = compat_sock_common_setsockopt,
//     .compat_getsockopt = compat_sock_common_getsockopt,
//     // .compat_ioctl      = inet_compat_ioctl,
// #endif
};
// EXPORT_SYMBOL(inet_dgram_ops);

struct proto nd_prot = {
    .name           = "ND",
    .owner          = THIS_MODULE,
    .close          = nd_lib_close,
    .pre_connect    = nd_pre_connect,
    .connect        = nd_v4_connect,
    .disconnect     = nd_disconnect,
    .accept         = nd_sk_accept,
    .ioctl          = nd_ioctl,
    .init           = nd_init_sock,
    .destroy        = nd_destroy_sock,
    .setsockopt     = nd_setsockopt,
    .getsockopt     = nd_getsockopt,
    .sendmsg        = nd_sendmsg,
    .recvmsg        = nd_recvmsg,
    .sendpage       = nd_sendpage,
    .backlog_rcv    = nd_v4_do_rcv,
    .release_cb     = nd_release_cb,
    .hash           = nd_hash,
    .unhash         = nd_unhash,
    // .rehash         = nd_v4_rehash,
    .get_port       = nd_sk_get_port,
    .memory_allocated   = &nd_memory_allocated,
    .sysctl_mem     = sysctl_nd_mem,
    .sysctl_wmem = &sysctl_nd_wmem_min,
    .sysctl_rmem = &sysctl_nd_rmem_min,
    .obj_size       = sizeof(struct nd_sock),
    .rsk_prot       = &nd_request_sock_ops,
    .h.hashinfo     = &nd_hashinfo,
    // .h.udp_table        = &nd_table,
    .max_header     = ND_HEADER_MAX_SIZE,
// #ifdef CONFIG_COMPAT
//     .compat_setsockopt  = compat_nd_setsockopt,
//     .compat_getsockopt  = compat_nd_getsockopt,
// #endif
    .diag_destroy       = nd_abort,
};
// EXPORT_SYMBOL(nd_prot);

/* Top-level structure describing the ND protocol. */

struct inet_protosw nd_protosw = {
        .type              = SOCK_DGRAM,
        .protocol          = IPPROTO_VIRTUAL_SOCK,
        .prot              = &nd_prot,
        .ops               = &nd_dgram_ops,
        .flags             = INET_PROTOSW_REUSE,
};

/* thinking of making this const? Don't.
 * early_demux can change based on sysctl.
 */
static struct net_protocol nd_protocol = {
        .early_demux =  nd_v4_early_demux,
        .early_demux_handler =  nd_v4_early_demux,
        .handler =      nd_rcv,
        .err_handler =  nd_err,
        .no_policy =    1,
        .netns_ok =     1,
};

/* Used to configure sysctl access to Homa configuration parameters.*/
static struct ctl_table nd_ctl_table[] = {
        {
                // this is only being called when unloading the module
                .procname       = "clean_match_sock",
                .data           = &nd_params.clean_match_sock,
                .maxlen         = sizeof(int),
                .mode           = 0644,
                .proc_handler   = nd_dointvec
        },
        {
                .procname       = "rmem_default",
                .data           = &nd_params.rmem_default,
                .maxlen         = sizeof(int),
                .mode           = 0644,
                .proc_handler   = nd_dointvec
        },
        {
                .procname       = "wmem_default",
                .data           = &nd_params.wmem_default,
                .maxlen         = sizeof(int),
                .mode           = 0644,
                .proc_handler   = nd_dointvec
        },
        {
                .procname       = "short_flow_size",
                .data           = &nd_params.short_flow_size,
                .maxlen         = sizeof(int),
                .mode           = 0644,
                .proc_handler   = nd_dointvec
        },
        {}
};

/*
 *      IPv4 request_sock destructor.
 */
static void nd_v4_reqsk_destructor(struct request_sock *req)
{

        printk("call reqsk destructor\n");
        printk("ireq option is NULL:%d\n", inet_rsk(req)->ireq_opt == NULL);
        kfree(rcu_dereference_protected(inet_rsk(req)->ireq_opt, 1));
}

struct request_sock_ops nd_request_sock_ops __read_mostly = {
        .family         =       PF_INET,
        .obj_size       =       sizeof(struct nd_request_sock),
        .rtx_syn_ack    =       NULL,
        .send_ack       =       NULL,
        .destructor     =       nd_v4_reqsk_destructor,
        .send_reset     =       NULL,
        .syn_ack_timeout =      NULL,
};


/* Used to remove sysctl values when the module is unloaded. */
static struct ctl_table_header *nd_ctl_header;

void nd_params_init(struct nd_params* params) {
    params->clean_match_sock = 0;
    params->match_socket_port = 3000;
    params->bandwidth = 100;
    params->control_pkt_rtt = 50;
    params->rtt = 50;
    params->bdp  = params->rtt * params->bandwidth / 8 * 1000;
    // params->bdp = 500000;
    // params->gso_size = 1500;
    // matchiing parameters
    params->alpha = 2;
    params->beta = 5;
    params->min_iter = 1;
    params->num_iters = 5;
    params->iter_size = params->beta * params->control_pkt_rtt * 1000;
    params->epoch_size = params->num_iters * params->iter_size * params->alpha;
    params->rmem_default = 3289600;
    params->wmem_default = 3289600;
    params->short_flow_size = params->bdp;
    params->control_pkt_bdp = params->control_pkt_rtt * params->bandwidth * 1000 / 8;
    params->data_budget = 1000000;
    printk("params->control_pkt_bdp:%d\n", params->control_pkt_bdp);
}
/**
 * nd_dointvec() - This function is a wrapper around proc_dointvec. It is
 * invoked to read and write sysctl values and also update other values
 * that depend on the modified value.
 * @table:    sysctl table describing value to be read or written.
 * @write:    Nonzero means value is being written, 0 means read.
 * @buffer:   Address in user space of the input/output data.
 * @lenp:     Not exactly sure.
 * @ppos:     Not exactly sure.
 * 
 * Return: 0 for success, nonzero for error. 
 */
int nd_dointvec(struct ctl_table *table, int write,
                void __user *buffer, size_t *lenp, loff_t *ppos)
{
        int result;
        result = proc_dointvec(table, write, buffer, lenp, ppos);
        if (write) {
                /* Don't worry which particular value changed; update
                 * all info that is dependent on any sysctl value.
                 */
                nd_sysctl_changed(&nd_params);

                // /* For this value, only call the method when this
                //  * particular value was written (don't want to increment
                //  * cutoff_version otherwise).
                //  */
                // if ((table->data == &homa_data.unsched_cutoffs)
                //                 || (table->data == &homa_data.num_priorities)) {
                //         homa_prios_changed(homa);
                // }
        }
        return result;
}

/**
 * nd_sysctl_changed() - Invoked whenever a sysctl value is changed;
 * any output-related parameters that depend on sysctl-settable values.
 * @params:    Overall data about the ND protocol implementation.
 */
void nd_sysctl_changed(struct nd_params *params)
{
        // __u64 tmp;

        // /* Code below is written carefully to avoid integer underflow or
        //  * overflow under expected usage patterns. Be careful when changing!
        //  */
        // homa->cycles_per_kbyte = (8*(__u64) cpu_khz)/homa->link_mbps;
        // homa->cycles_per_kbyte = (105*homa->cycles_per_kbyte)/100;
        // tmp = homa->max_nic_queue_ns;
        // tmp = (tmp*cpu_khz)/1000000;
        // homa->max_nic_queue_cycles = tmp;
    if(params->clean_match_sock == 1) {
        // sock_release(nd_match_table.sock);
        // nd_match_table.sock = NULL;
        // nd_epoch_destroy(&nd_epoch);
        params->clean_match_sock = 0;
    }
}
/**
 * nd_load() - invoked when this module is loaded into the Linux kernel
 * Return: 0 on success, otherwise a negative errno.
 */
static int __init nd_load(void) {
        int status;
        // struct timespec ts;
        // struct test_element e1, e2, e3, e4, e5;
        // struct test_element *temp;
        // struct nd_pq pq;
        // e1.value = 1;
        // e2.value = 6;
        // e3.value = 3;
        // e4.value = 4;
        // e5.value = 5;
        // nd_pq_init(&pq, test_compare);
        // nd_pq_push(&pq, &e5.node);
        // nd_pq_push(&pq, &e4.node);
        // nd_pq_push(&pq, &e3.node);
        // nd_pq_push(&pq, &e2.node);
        // nd_pq_push(&pq, &e1.node);
        //     printk("e5 pos:%p\n", &e5.node);
        // while(!nd_pq_empty(&pq)) {
        //     struct list_head *head;
        //     printk("num element:%d\n", pq.count);
        //     head = nd_pq_pop(&pq);
        //     temp = list_entry(head, struct test_element, node);
        //     printk("value: %d\n", temp->value);
        // }   
        printk(KERN_NOTICE "ND module loading\n");
        nd_params_init(&nd_params);

        nd_init();
        // nd_mattab_init(&nd_match_table, NULL);

        status = proto_register(&nd_prot, 1);
        if (status != 0) {
                printk(KERN_ERR "proto_register failed in nd_init: %d\n",
                    status);
                goto out;
        }
        inet_register_protosw(&nd_protosw);
        status = inet_add_protocol(&nd_protocol, IPPROTO_VIRTUAL_SOCK);

        if (status != 0) {
                printk(KERN_ERR "inet_add_protocol failed in nd_load: %d\n",
                    status);
                goto out_inet;
        }
        // nd_epoch_init(&nd_epoch);
        /* initialize rcv_core table and xmit_core table */
        // status = rcv_core_table_init(&rcv_core_tab);
        // if(status != 0) {
        //     goto out_cleanup;
        // }
        // status = xmit_core_table_init(&xmit_core_tab);
        // if(status != 0) {
        //     goto out_cleanup;
        // }
        // if (status)
        //         goto out_cleanup;
        // ndlite4_register();
        // metrics_dir_entry = proc_create("homa_metrics", S_IRUGO,
        //                 init_net.proc_net, &homa_metrics_fops);
        // if (!metrics_dir_entry) {
        //         printk(KERN_ERR "couldn't create /proc/net/homa_metrics\n");
        //         status = -ENOMEM;
        //         goto out_cleanup;
        // }

        nd_ctl_header = register_net_sysctl(&init_net, "net/nd",
                        nd_ctl_table);
        if (!nd_ctl_header) {
                printk(KERN_ERR "couldn't register ND sysctl parameters\n");
                status = -ENOMEM;
                goto out_nd_ctl_header;
        }
        
        // status = ndv4_offload_init();
        // printk("init the offload\n");
        // if (status != 0) {
        //         printk(KERN_ERR "ND couldn't init offloads\n");
        //         goto out_cleanup;
        // }
        // tasklet_init(&timer_tasklet, homa_tasklet_handler, 0);
        // hrtimer_init(&hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
        // hrtimer.function = &homa_hrtimer;
        // ts.tv_nsec = 1000000;                   /* 1 ms */
        // ts.tv_sec = 0;
        // tick_interval = timespec_to_ktime(ts);
        // hrtimer_start(&hrtimer, tick_interval, HRTIMER_MODE_REL);
        
        // tt_init("timetrace");
        /* load the nd connection target side */
        status = ndt_conn_init();
        if (status != 0) {
             pr_err("failed to allocate target side\n");
             goto out_ndt_conn;
        }
        status = nd_conn_init_module();
        if (status != 0) {
                pr_err("failed to allocate host side\n");
                goto out_nd_conn;
        }
        // nd_test_start();
        return 0;

out_cleanup:
        // unregister_net_sysctl_table(homa_ctl_header);
        // proc_remove(metrics_dir_entry);

        // if (ndv4_offload_end() != 0)
        //     printk(KERN_ERR "ND couldn't stop offloads\n");
        // nd_epoch_destroy(&nd_epoch);
        // rcv_core_table_destory(&rcv_core_tab);
        // xmit_core_table_destory(&xmit_core_tab);
out_nd_conn:
        nd_conn_cleanup_module();
out_ndt_conn:
        ndt_conn_exit();

out_nd_ctl_header:
        unregister_net_sysctl_table(nd_ctl_header);
        inet_del_protocol(&nd_protocol, IPPROTO_VIRTUAL_SOCK);
        printk("inet delete protocol\n");
out_inet:
        inet_unregister_protosw(&nd_protosw);
        printk("inet unregister protosw");
        proto_unregister(&nd_prot);
        printk("unregister protocol\n");
        // proto_unregister(&ndlite_prot);
out:
        nd_destroy();
        return status;
}

/**
 * nd_unload() - invoked when this module is unloaded from the Linux kernel.
 */
static void __exit nd_unload(void) {
        printk(KERN_NOTICE "ND module unloading\n");
        exiting = true;
        
        // tt_destroy();
        
        /* Stopping the hrtimer and tasklet is tricky, because each
         * reschedules the other. This means that the timer could get
         * invoked again after executing tasklet_disable. So, we stop
         * it yet again. The exiting variable will cause it to do
         * nothing, in case it triggers again before we cancel it the
         * second time. Very tricky! 
         */
        // hrtimer_cancel(&hrtimer);
        // tasklet_kill(&timer_tasklet);
        // hrtimer_cancel(&hrtimer);
        // if (homa_offload_end() != 0)
        //         printk(KERN_ERR "Homa couldn't stop offloads\n");
        // unregister_net_sysctl_table(homa_ctl_header);
        // proc_remove(metrics_dir_entry);
        
        /* clean up the target side logic */
        ndt_conn_exit();
        /* clean up the host side logic */
        nd_conn_cleanup_module();

        // if (ndv4_offload_end() != 0)
        //     printk(KERN_ERR "ND couldn't stop offloads\n");
        printk("start to unload\n");
        // nd_epoch_destroy(&nd_epoch);
        unregister_net_sysctl_table(nd_ctl_header);
        printk("unregister sysctl table\n");
        // rcv_core_table_destory(&rcv_core_tab);
        // xmit_core_table_destory(&xmit_core_tab);

        // nd_mattab_destroy(&nd_match_table);
        // printk("remove match table\n");

        nd_destroy();
        printk("remove nd table\n");

        inet_del_protocol(&nd_protocol, IPPROTO_VIRTUAL_SOCK);
        printk("reach here:%d\n", __LINE__);
        inet_unregister_protosw(&nd_protosw);
        printk("reach here:%d\n", __LINE__);
        proto_unregister(&nd_prot);
        printk("reach here:%d\n", __LINE__);


        // proto_unregister(&ndlite_prot);
}

module_init(nd_load);
module_exit(nd_unload);
