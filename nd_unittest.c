/* unit test */
#include "nd_unittest.h"
static void test_set_up_ip_hdr(struct sk_buff* skb) {
	struct iphdr *iph;
	iph = skb_put(skb, sizeof(struct iphdr));
	iph->version = 4;
	iph->ihl = 5;
	iph->tos = 0;
	iph->frag_off = 0;
	iph->saddr = 1000;
	iph->daddr = 2000;
    skb_reset_network_header(skb);
    skb_pull(skb, sizeof(struct iphdr));
}
static void test_set_up_tcp_hdr(struct sk_buff* skb) {
	struct tcphdr *tcph;
	tcph = skb_put(skb, sizeof(struct tcphdr));
    skb_reset_transport_header(skb);
    skb_pull(skb, sizeof(struct tcphdr));
}

static void test_set_up_nd_hdr(struct sk_buff *skb) {
    struct ndhdr *nh;
    static int source = 1000;
	nh = skb_put(skb, sizeof(struct ndhdr));
	nh->type = SYNC;
    nh->source = source;
    nh->dest = 2000;
    source++;
}

static void test_set_up_nd_data_hdr(struct sk_buff *skb) {
    struct ndhdr *nh;
    static int source = 1000;
	nh = skb_put(skb, sizeof(struct ndhdr));
	nh->type = DATA;
    nh->source = source;
    nh->dest = 2000;
    nh->segment_length = 2000;
    source++;
    skb_put(skb, 2000);
}

static void test_set_up_nd_data_hdr2(struct sk_buff *skb, int bytes) {
    struct ndhdr *nh;
    static int source = 1000;
	nh = skb_put(skb, sizeof(struct ndhdr));
	nh->type = DATA;
    nh->source = source;
    nh->dest = 2000;
    nh->segment_length = 3000;
    source++;
    skb_put(skb, bytes);
}

static void test_set_up_data_bytes(struct sk_buff *skb, int bytes) {
    struct ndhdr *nh;
    // static int source = 1000;
	nh = skb_put(skb, bytes);
}

static void test_pass_to_vs_layer_1(void) {
    struct sk_buff_head receive_queue;
    struct sk_buff *skb1 = alloc_skb(500, GFP_ATOMIC);
    struct sk_buff *skb2, *skb3, *skb4;
    test_set_up_ip_hdr(skb1);
    test_set_up_tcp_hdr(skb1);
    skb2 = skb_copy(skb1, GFP_ATOMIC);
    skb3 = skb_copy(skb1, GFP_ATOMIC);
    skb4 = skb_copy(skb1, GFP_ATOMIC);
    test_set_up_nd_hdr(skb1);
    test_set_up_nd_hdr(skb2);
    test_set_up_nd_hdr(skb3);
    test_set_up_nd_hdr(skb4);
    skb_queue_head_init(&receive_queue);
    skb_queue_head(&receive_queue, skb1);
    skb_queue_head(&receive_queue, skb2);
    skb_queue_head(&receive_queue, skb3);
    skb_queue_head(&receive_queue, skb4);
    printk("---------test---------");
    // pass_to_vs_layer(&receive_queue);

}

/* data header */
static void test_pass_to_vs_layer_2(void) {
    struct sk_buff_head receive_queue;
    struct sk_buff *skb1 = alloc_skb(5500, GFP_ATOMIC);
    struct sk_buff *skb2, *skb3, *skb4;
    test_set_up_ip_hdr(skb1);
    test_set_up_tcp_hdr(skb1);
    skb2 = skb_copy(skb1, GFP_ATOMIC);
    skb3 = skb_copy(skb1, GFP_ATOMIC);
    skb4 = skb_copy(skb1, GFP_ATOMIC);
    test_set_up_nd_data_hdr(skb1);
    test_set_up_nd_data_hdr(skb2);
    test_set_up_nd_data_hdr(skb3);
    test_set_up_nd_data_hdr(skb4);
    skb_queue_head_init(&receive_queue);
    skb_queue_head(&receive_queue, skb1);
    skb_queue_head(&receive_queue, skb2);
    skb_queue_head(&receive_queue, skb3);
    skb_queue_head(&receive_queue, skb4);
    printk("---------test---------");
    // pass_to_vs_layer(&receive_queue);

}

/* test split */
static void test_pass_to_vs_layer_3(void) {
    struct sk_buff_head receive_queue;
    struct sk_buff *skb1 = alloc_skb(64000, GFP_ATOMIC);
    test_set_up_ip_hdr(skb1);
    test_set_up_tcp_hdr(skb1);

    test_set_up_nd_data_hdr(skb1);
    test_set_up_nd_data_hdr(skb1);
    test_set_up_nd_data_hdr(skb1);
    test_set_up_nd_data_hdr(skb1);
    skb_queue_head_init(&receive_queue);
    skb_queue_head(&receive_queue, skb1);
    printk("---------test---------");
    // pass_to_vs_layer(&receive_queue);

}
static void test_pass_to_vs_layer_4(void) {
    struct sk_buff_head receive_queue;
    struct sk_buff *skb1 = alloc_skb(500, GFP_ATOMIC);
    test_set_up_ip_hdr(skb1);
    test_set_up_tcp_hdr(skb1);

    test_set_up_nd_hdr(skb1);
    test_set_up_nd_hdr(skb1);
    test_set_up_nd_hdr(skb1);
    test_set_up_nd_hdr(skb1);
    skb_queue_head_init(&receive_queue);
    skb_queue_head(&receive_queue, skb1);
    printk("---------test---------");
    // pass_to_vs_layer(&receive_queue);

}

static void test_pass_to_vs_layer_5(void) {
    struct sk_buff_head receive_queue;
    struct sk_buff *skb1 = alloc_skb(64000, GFP_ATOMIC);
    struct sk_buff *skb2;
    test_set_up_ip_hdr(skb1);
    test_set_up_tcp_hdr(skb1);
    skb2 = skb_copy(skb1, GFP_ATOMIC);

    test_set_up_nd_data_hdr2(skb1, 2000);
    test_set_up_data_bytes(skb2,1000);
    test_set_up_nd_hdr(skb2);
    skb_queue_head_init(&receive_queue);
    skb_queue_head(&receive_queue, skb2);
    skb_queue_head(&receive_queue, skb1);
    printk("---------test---------");
    // pass_to_vs_layer(&receive_queue);

}

static void test_pass_to_vs_layer_6(void) {
    struct sk_buff_head receive_queue;
    struct sk_buff *skb1 = alloc_skb(64000, GFP_ATOMIC);
    struct sk_buff *skb2, *skb3, * skb4;
    test_set_up_ip_hdr(skb1);
    test_set_up_tcp_hdr(skb1);
    skb2 = skb_copy(skb1, GFP_ATOMIC);
    skb3 = skb_copy(skb1, GFP_ATOMIC);
    skb4 = skb_copy(skb1, GFP_ATOMIC);

    test_set_up_nd_data_hdr2(skb1, 2000);
    test_set_up_data_bytes(skb2,100);
    test_set_up_data_bytes(skb3,100);
    test_set_up_data_bytes(skb4,800);

    test_set_up_nd_hdr(skb4);
    skb_queue_head_init(&receive_queue);
    skb_queue_head(&receive_queue, skb4);
    skb_queue_head(&receive_queue, skb3);
    skb_queue_head(&receive_queue, skb2);
    skb_queue_head(&receive_queue, skb1);
    printk("---------test---------");
    // pass_to_vs_layer(&receive_queue);

}

static void test_pass_to_vs_layer_7(void) {
    struct sk_buff_head receive_queue;
    struct sk_buff *skb1 = alloc_skb(64000, GFP_ATOMIC);
    test_set_up_ip_hdr(skb1);
    test_set_up_tcp_hdr(skb1);
    skb_queue_head_init(&receive_queue);
    test_set_up_data_bytes(skb1, 10);
    skb_queue_head(&receive_queue, skb1);
    printk("---------test---------\n");
    // pass_to_vs_layer(&receive_queue);
    kfree_skb(skb1);

}

static void test_pass_to_vs_layer_8(void) {
    struct sk_buff_head receive_queue;
    struct sk_buff *skb1 = alloc_skb(64000, GFP_ATOMIC);
    struct sk_buff *skb2;
    test_set_up_ip_hdr(skb1);
    test_set_up_tcp_hdr(skb1);
    skb2 = skb_copy(skb1, GFP_ATOMIC);

    test_set_up_nd_data_hdr2(skb1, 2000);
    test_set_up_data_bytes(skb2,500);
    skb_queue_head_init(&receive_queue);
    skb_queue_head(&receive_queue, skb2);
    skb_queue_head(&receive_queue, skb1);
    printk("---------test---------");
    // pass_to_vs_layer(&receive_queue);
    while ((skb1 = skb_dequeue(&receive_queue)) != NULL) {
        printk("free skb\n");
        kfree(skb1);
    }
}

void nd_test_start(void) {
    // test_pass_to_vs_layer_1();
    // test_pass_to_vs_layer_2();
//    test_pass_to_vs_layer_3();
    // test_pass_to_vs_layer_4();
    // test_pass_to_vs_layer_5();
    // test_pass_to_vs_layer_6();
        // test_pass_to_vs_layer_8();
}