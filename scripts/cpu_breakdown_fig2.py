import csv 
import requests 
import xml.etree.ElementTree as ET 
import sys
data_cpy = {"csum_and_copy_from_iter_full", "skb_copy_bits", "__memcpy", "memcpy_to_page", "csum_partial_copy_generic", "skb_copy_datagram_iter", "check_stack_object", "copyout", "simple_copy_to_iter", "iov_iter_advance", "__virt_addr_valid", "copy_user_enhanced_fast_string", "memcpy_erms", "__check_object_size",
 "__skb_datagram_iter","_copy_from_iter_full", "_copy_to_iter"}
system_call = {"aa_file_perm", "__fget_light", "__fsnotify_parent", "__vfs_read", "fsnotify", "fput_many", "common_file_perm", "inet_recvmsg", "new_sync_write", "__x64_sys_read", "__x64_sys_write", "ksys_write", "ksys_read", "vfs_write", "__libc_read", "new_sync_read", "__fget_files", "vfs_read", "sock_read_iter", "sock_write_iter","vfs_write","sock_sendmsg"}
net_driver = {"nd_page_pool_recycle_skb_pages", "ndt_tcp_read_sock", "nd_page_pool_recycle_pages", "nd_dequeue_snd_q", "nd_conn_try_send_cmd_pdu","nd_dcopy_sche_rr", "__get_user_pages","nd_snd_q_ready.part.0", "sk_wait_sender_data_copy.isra.0", "nd_rbtree_insert", "follow_page_mask", "nd_try_dcopy_send","follow_page_pte","mark_page_accessed", "nd_release_cb", "nd_fetch_dcopy_response", "nd_try_send_ack.part.0", 
"ndt_conn_io_work", "nd_recvmsg_new_2", "nd_split_and_merge", "nd_clean_dcopy_pages", "nd_recvmsg_new", "nd_handle_data_skb", "nd_add_backlog", "nd_data_queue", "__nd_lookup_established", 
"nd_sendmsg", "nd_push", "nd_v4_do_rcv", "nd_handle_ack_pkt",  "nd_conn_queue_request","nd_recvmsg", "nd_recvmsg", "nd_handle_data_skb_new", "nd_queue_origin_skb", 
"ndt_conn_try_recv", "ndt_recv_skbs", "nd_conn_sche_rr", "nd_try_dcopy_receive", "nd_handle_data_pkt", "nd_dcopy_queue_request", "__nd_try_merge_page.part.0", 
"nd_dcopy_iov_init.constprop.0", "nd_try_coalesce.part.0", "nd_try_dcopy", "nd_conn_try_send", "nd_conn_try_send_data_pdu", "queue_work_on", "pass_to_vs_layer", "nd_split"}
tcp_ip_p = {"tcp_small_queue_check.isra.0", "tcp_sendpage_locked","tcp_send_mss", "__netif_receive_skb", "sock_recvmsg", "tcp_sendmsg", "inet_send_prepare", "security_sock_rcv_skb", "__cgroup_bpf_run_filter_skb", "tcp_sendpage", "kernel_sendpage", "tcp_ack_update_rtt.isra.0", "tcp_data_queue", "tcp_urg", "tcp_push", "inet_sendpage", "tcp_read_sock", "tcp_recv_skb", 
"tcp_recv_timestamp", "ip_rcv_finish_core.isra.0", "ip_rcv_core.isra.0", "do_tcp_sendpages", "tcp_grow_window.isra.36", "tcp_newly_delivered", "ip_finish_output", "tcp_rearm_rto", 
"__tcp_v4_send_check", "ip_protocol_deliver_rcu", "tcp_rack_advance", "tcp_push_one", "tcp_rate_skb_delivered", "tcp_chrono_stop", "tcp_options_write", "ip_local_out", "tcp_rate_skb_sent",
 "tcp_update_skb_after_send", "ip_queue_xmit", "tcp_stream_memory_free", "ip_sublist_rcv", "ip_rcv_core.isra.20", "__ip_finish_output", "tcp_ack_update_rtt.isra.45",
 "__ip_local_out", "tcp_schedule_loss_probe", "ip_rcv_finish_core.isra.18", "tcp_tasklet_func", "tcp_release_cb", "release_sock", 
"tcp_send_delayed_ack", "ip_copy_addrs", "tcp_mstamp_refresh","__tcp_send_ack.part.46", "ip_rcv_finish", "ip_rcv", "tcp_cleanup_rbuf", "ip_local_deliver_finish", 
"tcp_v4_inbound_md5_hash", "tcp_rcv_space_adjust", 
"tcp_v4_fill_cb", "inet_ehashfn", "tcp_established_options", "tcp_validate_incoming", "tcp_event_new_data_sent", 
"tcp_update_pacing_rate", "tcp_small_queue_check.isra.34", "tcp_ack_update_rtt.isra.45", "tcp_current_mss", "tcp_check_space", 
"tcp_tasklet_func", "__sys_recvfrom", "ip_rcv_core.isra.21", "ip_rcv_finish_core.isra.19", "ip_output", "tcp_v4_send_check", "ip_local_deliver", "ip_finish_output2", 
"ipv4_mtu", "__ip_queue_xmit", "__xfrm_policy_check2.constprop.43", "sk_filter_trim_cap", "__tcp_select_window", "tcp_data_ready", 
"rb_next", "rb_first", "rb_erase", "tcp_trim_head", "tcp_rbtree_insert", "tcp_event_data_recv", "__sock_wfree", "ipv4_dst_check",
"tcp_recvmsg", "__tcp_transmit_skb", "rb_insert_color", "__release_sock", "tcp_grow_window.isra.37", 
"tcp_v4_do_rcv","tcp_wfree", "tcp_sendmsg_locked", "sock_put", "__inet_lookup_established",
"tcp_rcv_established", "tcp_add_backlog", "tcp_try_coalesce", "tcp_v4_rcv", "tcp_v4_early_demux",
"tcp_queue_rcv", "sock_rfree", "tcp_ack", "sk_free", "ip_send_check", "tcp_write_xmit", "__tcp_ack_snd_check"}
skb = {"__pskb_pull_tail", "kfree_skb", "nd_try_dcopy_receive", "nd_rfree", "skb_zerocopy_clone","skb_mac_gso_segment", "sk_stream_alloc_skb", "__kfree_skb", "skb_entail", "netif_skb_features", "skb_push", "skb_free_head", "skb_release_all", 
"skb_split", "skb_release_head_state", "skb_put", "__build_skb_around", "__skb_get_hash", "__skb_flow_dissect", "skb_headers_offset_update", "skb_add_rx_frag", "skb_page_frag_refill", "__copy_skb_header", "pskb_expand_head", "skb_segment", "skb_release_data", 
"__alloc_skb", "skb_try_coalesce", "build_skb", "__build_skb" , "__skb_clone", "skb_clone"}
memory = {"gup_pgd_range", "page_mapping", "set_page_dirty", "nd_release_pages", "iov_iter_get_pages", "get_user_pages_fast", "kmem_cache_alloc_trace", "page_pool_refill_alloc_cache", "free_pcp_prepare", "free_unref_page_prepare.part.0",
 "__kmalloc_reserve.isra.0", "memset_erms", "clear_page_erms", 
"kmalloc_slab", "__slab_alloc", " __kmalloc_reserve.isra.62", "page_frag_free","__put_page", "mem_cgroup_uncharge", 
 "__page_pool_alloc_pages_slow", "__page_cache_release", "__zone_watermark_ok", "new_slab", "page_pool_alloc_pages", "__mod_zone_page_state", 
"page_frag_alloc", "free_unref_page_prepare.part.75", "free_unref_page_commit", "prep_new_page", 
"kfree_skbmem", "unfreeze_partials.isra.80", "get_partial_node.isra.81", "free_one_page", "free_unref_page", "__page_pool_put_page",
 "__page_pool_clean_page", "__slab_free", "__free_pages_ok", "__alloc_pages_nodemask", "___slab_alloc", "kfree", "kmem_cache_alloc", "kmem_cache_alloc_node", "__kmalloc_node_track_caller",
"kmem_cache_free_bulk", "get_page_from_freelist", "free_pcppages_bulks","free_pcppages_bulk", "kmem_cache_free", "__ksize"}
lock = {"lock_sock_nested", "_raw_read_lock_bh", "_raw_read_unlock_bh", "set_page_dirty_lock", "unlock_page", "mutex_lock", "mutex_unlock", "_raw_spin_lock_irq", "_raw_spin_unlock_bh", "_raw_spin_trylock", "native_queued_spin_lock_slowpath", "_raw_spin_unlock_irqrestore", "_raw_spin_lock", "_raw_spin_lock_bh", "_raw_spin_lock_irqsave"}
network_sub = {"fq_codel_dequeue", "mlx5e_ipsec_feature_check", "eth_header", "validate_xmit_skb", "__radix_tree_lookup", "napi_skb_free_stolen_head", "mlx5e_tls_handle_rx_skb", "napi_gro_complete", "tcp4_gro_complete", "inet_gro_complete", "mlx5_eq_cq_get", 
"dma_direct_sync_single_for_device", "skb_gro_reset_offset", "netdev_core_pick_tx", "dev_queue_xmit", "mlx5e_free_rx_mpwqe", "mlx5e_poll_xdpsq_cq", "net_tx_action", "__netif_receive_skb_one_core", "sch_direct_xmit", "napi_schedule_prep","napi_complete_done", "__napi_alloc_skb", "enqueue_to_backlog", "netif_receive_skb_list_internal", 
"__qdisc_run", "process_backlog", "mlx5e_features_check", "mlx5e_poll_ico_cq", "__get_xps_queue_idx", "__napi_schedule", "get_rps_cpu", "mlx5_cq_tasklet_cb", 
"mlx5e_select_queue", "mlx5_irq_int_handler", "mlx5e_completion_event",  "memcmp", "eth_type_trans", 
"dma_direct_sync_single_for_cpu", "__dev_queue_xmit", "pfifo_fast_enqueue", "napi_gro_receive", "tcp4_gro_receive", "inet_gso_segment", "__netif_receive_skb_core", "net_rx_action",
 "mlx5e_napi_poll", "dma_direct_unmap_page", "dev_hard_start_xmit", "tcp_gso_segment", "dma_direct_map_page", 
"mlx5e_poll_tx_cq", "mlx5e_handle_rx_dim", "mlx5e_post_rx_mpwqes",
 "mlx5e_skb_from_cqe_mpwrq_nonlinear", "mlx5e_handle_rx_cqe_mpwrq", "mlx5e_sq_xmit", "mlx5e_page_release_dynamic",
  "mlx5e_xmit", "napi_consume_skb", "dma_direct_map_pagef", "mlx5e_skb_from_cqe_mpwrq_linear",
"tcp_gro_receive", "dev_gro_receive", "mlx5_eq_comp_int", "skb_gro_receive", "mlx5e_xdp_handle", 
"mlx5e_build_rx_skb", "inet_gro_receive", "mlx5e_poll_rx_cq", "pfifo_fast_dequeue"}
schedule={"__calc_delta","update_min_vruntime", "update_rq_clock", "rcu_note_context_switch", "cgroup_rstat_updated", "load_new_mm_cr3", "sk_wait_data_copy.isra.0", "pick_next_entity", "account_entity_enqueue", "put_prev_entity", "cpuacct_charge", "dequeue_entity", "set_next_entity", "check_preempt_wakeup", "deactivate_task", "cpuidle_enter", "psi_task_change", "schedule_idle", "sched_clock_cpu", "sched_clock", "sched_clock_cpu", "tasklet_action", "tasklet_action_common.isra.22", "__tasklet_schedule_common", "insert_work", "worker_thread", "activate_task", "process_one_work", "tasklet_action_common.isra.0", "pick_next_task_idle", "put_prev_task_fair", "try_to_wake_up", "call_cpuidle", "schedule", "__switch_to", "__switch_to_asm", "do_syscall_64",  
"syscall_return_via_sysret", "entry_SYSCALL_64", "cpuidle_enter_state", "wait_woken","read_tsc", "sock_def_readable", "__schedule", "woken_wake_function", "switch_mm_irqs_off", 
"dequeue_task_fair", "update_curr", "enqueue_task_fair", "pick_next_task_fair", "sk_wait_data", "schedule_timeout", 
"_cond_resched","reweight_entity", "interrupt_entry", "finish_task_switch", "__local_bh_enable_ip", "enqueue_entity"}
etc = {"rcu_idle_enter", "rcu_idle_exit", "handle_edge_irq", "newidle_balance", "menu_reflect", "native_apic_msr_eoi_write", "__libc_recv", "update_load_avg", "__siphash_aligned","enqueue_timer", "__update_load_avg_cfs_rq", "refresh_cpu_vm_stats", "do_idle", 
"dso__find_symbol", "native_sched_clock", "__next_timer_interrupt", "ioread32", 
"native_write_msr", "ktime_get", "__do_softirq", "update_cfs_group","switch_fpu_return", "__update_load_avg_se",
  "__x86_indirect_thunk_rax", "sched_ttwu_pending", "llist_add_batch", "PageHuge", "update_sd_lb_stats", "update_blocked_averages",
   "find_next_bit", "__symbols__insert", "menu_select", "native_irq_return_iret", "get_nohz_timer_target",
 "mod_timer"}

class Profiling:
    dc_cost = 0.0
    system_cost = 0.0
    nd_cost = 0.0
    tcp_ip_cost = 0.0
    skb_cost = 0.0
    memory_cost = 0.0
    lock_cost = 0.0
    network_sub_cost = 0.0
    etc_cost = 0.0
    schedule_cost = 0.0

def output_file(filename, p, util):
    f = open(filename, "w+")
    f.write("{} {:.2f}\n".format("data copy :", util*p.dc_cost))
    f.write("{} {:.2f}\n".format("     lock :", util*p.lock_cost))
    f.write("{} {:.2f}\n".format("   netdev :", util*p.network_sub_cost))
    f.write("{} {:.2f}\n".format("      skb :", util*p.skb_cost))
    f.write("{} {:.2f}\n".format("     etc. :", util*p.etc_cost))
    f.write("{} {:.2f}\n".format("       mm :", util*p.memory_cost))
    f.write("{} {:.2f}\n".format("    sched :", util*p.schedule_cost))
    f.write("{} {:.2f}\n".format("   tcp/ip :", util*p.tcp_ip_cost))

def parse_contri(filename="../results/nsdi2021/oto/baseline_s",util=1.0):
    p = Profiling()
    with open(filename) as f:
        lines = f.readlines()
        for i in range(len(lines)):
            if lines[i][0] == "#":
                continue
            # if i > 40:
            #     break
            params = lines[i].split()
            if len(params) < 5:
                continue
            precentage = float(params[0][:-1]) / 100.0
            function = params[4]
            if function in data_cpy:
                p.dc_cost += precentage
            elif function in tcp_ip_p:
                p.tcp_ip_cost += precentage
            elif function in system_call:
                p.system_cost += precentage
            elif function in net_driver:
                p.nd_cost += precentage
            elif function in skb:
                p.skb_cost += precentage
            elif function in memory:
                p.memory_cost += precentage
            elif  function in lock:
                p.lock_cost += precentage
            elif  function in network_sub:
                p.network_sub_cost += precentage 
            elif function in schedule:
                p.schedule_cost += precentage
            elif  function in etc:
                # print lines[i]
                # print params
                p.etc_cost += precentage

            else:
                #print (lines[i])
                p.etc_cost += precentage
    output_file(filename + "_result", p, util)

def main():
    trace = str(sys.argv[1])
    util = float(str(sys.argv[2]))
    parse_contri(trace,util)

    # parse_contri("../result/" + "{}/all_old_data_copy_r".format(trace))
    # parse_contri("../result/" + "{}/6MB/all_r".format(trace))
    # parse_contri("../result/" + "{}/6MB_128_page_pool/all_r".format(trace))

    # parse_contri("../result/" + "{}/10MB/all_r".format(trace))
    # parse_contri("../result/" + "{}/6MB_single_core/all_r".format(trace))
    # parse_contri("../result/" + "{}/6MB_no_page_pool/all_r".format(trace))

    # parse_contri("../result/" + "{}/all_s_new".format(trace))
    # parse_contri("../result/" + "{}/all_nd_s".format(trace))
    # parse_contri("../result/" + "{}/all_nd_r".format(trace))

    # parse_contri("../result/" + "{}/app_r".format(trace))
    # parse_contri("../result/" + "{}/all_tcp_s".format(trace))
    # parse_contri("../result/" + "{}/all_tcp_s_new".format(trace))
    # parse_contri("../result/" + "{}/all_r_has_irq".format(trace))
    # parse_contri("../result/" + "{}/all_r_no_irq".format(trace))
    # parse_contri("../result/" + "{}/all_s_short_flows".format(trace))

    # parse_contri("../result/" + "{}/channel_r".format(trace))
    # parse_contri("../result/" + "{}/channel_s".format(trace))
    # parse_contri("../result/" + "{}/dcopy_r".format(trace))
    # parse_contri("../result/" + "{}/dcopy_s".format(trace))
    # parse_contri("../result/" + "{}/all_r".format(trace))

    # parse_contri("../result/" + "{}/app_r".format(trace))
    # parse_contri("../result/" + "{}/dcopy_r".format(trace))
    # parse_contri("../result/" + "{}/pkt_pro_r".format(trace))

    # parse_contri("../result/" + "{}/baseline_s".format(trace))
    # parse_contri("../result/" + "{}/baseline_r".format(trace))
    # parse_contri("../result/" + "{}/tso_gro_s".format(trace))
    # parse_contri("../result/" + "{}/tso_gro_r".format(trace))
    # parse_contri("../result/" + "{}/jumbo_s".format(trace))
    # parse_contri("../result/" + "{}/jumbo_r".format(trace))
    # parse_contri("../result/" + "{}/rfs_s".format(trace))
    # parse_contri("../result/" + "{}/rfs_r".format(trace))
main()
