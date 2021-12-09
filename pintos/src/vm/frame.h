#ifndef VM_FRAME_H
#define VM_FRAME_H
#include <hash.h>
#include "vm/page.h"
#include "threads/palloc.h"

struct hash frame_table;

struct frame
{
    struct hash_elem hash_elem;
    int32_t frame_addr;
    struct page *page;
    int owner_id;
    int unused_count;
};
struct lock frame_table_lock;
struct lock frame_allocation_lock;
void frame_table_init();
void *frame_allocator_get_user_page(struct page *page, enum palloc_flags flags, bool writable);
void frame_allocator_free_user_page(void *kernel_vaddr, bool locked);
void frame_map(void *frame_addr, struct page *page, bool writable);
void frame_map(void *frame_addr, struct page *page, bool writable);
void frame_unmap(void *frame_addr);
void pin_frame(void *kaddr);
void unpin_frame(void *kaddr);

static unsigned frame_hash(const struct hash_elem *e, void *aux);
static bool frame_less(const struct hash_elem *a, const struct hash_elem *b, void *aux);
static void *frame_allocator_evict_page(void);
static struct frame *frame_allocator_choose_eviction_frame(void);
static void frame_allocator_save_frame(struct frame *);
#endif