#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/ptr_ring.h>

#include <net/page_pool.h>
#include <linux/dma-direction.h>
#include <linux/dma-mapping.h>
#include <linux/page-flags.h>
#include <linux/mm.h> /* for __put_page() */

#include <trace/events/page_pool.h>

#include "nd_impl.h"

/* copy from page_pool.c */
static void page_pool_dma_sync_for_device(struct page_pool *pool,
					  struct page *page,
					  unsigned int dma_sync_size)
{
	dma_sync_size = min(dma_sync_size, pool->p.max_len);
	dma_sync_single_range_for_device(pool->p.dev, page->dma_addr,
					 pool->p.offset, dma_sync_size,
					 pool->p.dma_dir);
}

/* get dma address for recycle pages */
bool nd_page_pool_dma_map_page(struct page_pool *pool, struct page *page)
{
    dma_addr_t dma;
    if (!page)
        return false;

    /* mellanox driver will skip this */
    if (!(pool->p.flags & PP_FLAG_DMA_MAP)) {
        goto skip_dma_map;
    }

    /* Setup DMA mapping: use 'struct page' area for storing DMA-addr
        * since dma_addr_t can be either 32 or 64 bits and does not always fit
        * into page private data (i.e 32bit cpu with 64bit DMA caps)
        * This mapping is kept for lifetime of page, until leaving pool.
        */
    dma = dma_map_page_attrs(pool->p.dev, page, 0,
                                (PAGE_SIZE << pool->p.order),
                                pool->p.dma_dir, DMA_ATTR_SKIP_CPU_SYNC);
    if (dma_mapping_error(pool->p.dev, dma)) {
        printk("dma mapping error\n");
        return false;
    }
    page->dma_addr = dma;

    if (pool->p.flags & PP_FLAG_DMA_SYNC_DEV){
        WARN_ON_ONCE(true);
        page_pool_dma_sync_for_device(pool, page, pool->p.max_len);
    }

skip_dma_map:
//     /* Track how many pages are held 'in-flight' */
//     pool->pages_state_hold_cnt++;

//     trace_page_pool_state_hold(pool, page, pool->pages_state_hold_cnt);

    /* When page just alloc'ed is should/must have refcnt 1. */
    return true;
}

void nd_page_pool_dma_unmap_page(struct page_pool *pool, struct page *page) {
    dma_addr_t dma;
    if (!(pool->p.flags & PP_FLAG_DMA_MAP))
		return;
	dma = page->dma_addr;
	dma_unmap_page_attrs(pool->p.dev, dma,
			     PAGE_SIZE << pool->p.order, pool->p.dma_dir,
			     DMA_ATTR_SKIP_CPU_SYNC);
	page->dma_addr = 0;
    return;
}

void nd_page_pool_recycle_skb_pages(struct sk_buff *skb, struct page_pool* page_pool) {
    struct page *page;
    int refcnt, i;

    for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
        page = skb_frag_page(&skb_shinfo(skb)->frags[i]);
        refcnt = page_ref_count(page);
        /* Todo: solve the the corner case: when page ref count = 2, the race condition could happen; */
        if(refcnt > 1) {
            put_page(page);
        } else {
            if(!nd_page_pool_dma_map_page(page_pool, page)) {
                goto normal_path;
            }
            // printk("put into page pool:%p\n", page);
            if(ptr_ring_produce_bh(&page_pool->ring, page) != 0) {
                // printk("ring is full\n");
                goto dma_unmap;
            }
            /* this part is needed to change */
            atomic_inc(&page_pool->pages_state_hold_cnt);
            continue;
dma_unmap:
            /* ring buffer is full; go to the normal path */
            // printk("dma unmap\n");
            if (page_pool->p.flags & PP_FLAG_DMA_MAP) {
                nd_page_pool_dma_unmap_page(page_pool, page);
            }
normal_path:
            // printk("normal path\n");
            put_page(page);
        }
    }
    skb_shinfo(skb)->nr_frags = 0;
}

/* this method assumes page pool is still valid; If the recv queue of NIC driver
 * is frequently recreated, then this optimization should be off. 
 * ToDo: Rather than piggybacking page pool address, storing receive queue id and
 * only recycles the receive queue if it is not destroyed.
 */
void nd_page_pool_recycle_pages(struct sk_buff *skb) {
    struct page_pool *page_pool = skb_shinfo(skb)->page_pool;
    // struct page *page;
    struct sk_buff *segs;
    // int refcnt, i;
    if(!page_pool) {
        // WARN_ON_ONCE(true);
        return;
    }
	if (skb->cloned && atomic_read(&skb_shinfo(skb)->dataref) > 1) {
        // WARN_ON_ONCE(true);
		return;
    }
    /* free pages of the head skb */
    nd_page_pool_recycle_skb_pages(skb, page_pool);

    /* go through frag_list of each skb */
    segs = skb_shinfo(skb)->frag_list;
    while (segs) {
		struct sk_buff *next = segs->next;
        /* free pages of the skb list */
		nd_page_pool_recycle_skb_pages(segs, page_pool);
		segs = next;
	}
}
