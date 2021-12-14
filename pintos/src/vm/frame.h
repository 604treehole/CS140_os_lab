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
void pin_frame(void *kaddr);
void unpin_frame(void *kaddr);
#endif