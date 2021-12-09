#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"
#include <debug.h>
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
void frame_table_init(void)
{
    hash_init(&frame_table, frame_hash, frame_less, NULL);
    lock_init(&frame_table_lock);
    lock_init(&frame_allocation_lock);
}
static struct frame *find_frame_by_kaddr(void *kaddr)
{
    struct frame new_fr;
    new_fr.frame_addr = kaddr;
    struct hash_elem *e = hash_find(&frame_table, &(new_fr.hash_elem));
    if (e == NULL)
        return NULL;
    return hash_entry(e, struct frame, hash_elem);
}
// struct frame* frame_find()
/*在frame_table上分配一个frame并映射到page*/
void frame_map(void *frame_addr, struct page *page, bool writable)
{
    struct frame *new_fr = NULL;
    new_fr = malloc(sizeof(struct frame)); //在内存上分配一个frame
    if (!new_fr)
        PANIC("Failed to malloc memory for struct frame");

    new_fr->page = page;
    new_fr->frame_addr = frame_addr;
    new_fr->owner_id = thread_current()->tid;
    new_fr->unused_count = 0;
    page->kaddr = frame_addr;
    lock_acquire(&frame_table_lock);
    hash_insert(&frame_table, &new_fr->hash_elem); //插入frame
    lock_release(&frame_table_lock);
}
/*将frame_addr处的frame在frame_table中去除，即解除了该frame向page的映射*/
void frame_unmap(void *frame_addr)
{
    struct frame f;
    f.frame_addr = frame_addr;

    lock_acquire(&frame_table_lock);
    hash_delete(&frame_table, &f.hash_elem);
    lock_release(&frame_table_lock);
}

/*frame_table的hash函数*/
static unsigned frame_hash(const struct hash_elem *e, void *aux UNUSED)
{
    const struct frame *f = hash_entry(e, struct frame, hash_elem);
    return hash_bytes(&f->frame_addr, sizeof(f->frame_addr));
}
static bool frame_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    const struct frame *frame_a = hash_entry(a, struct frame, hash_elem);
    const struct frame *frame_b = hash_entry(b, struct frame, hash_elem);
    return frame_a->frame_addr < frame_b->frame_addr;
}
/*将page和frame_table的一个frame对应起来，并返回该帧的物理地址(=kernel_vaddr)*/
void *frame_allocator_get_user_page(struct page *page, enum palloc_flags flags, bool writable)
{
    lock_acquire(&frame_allocation_lock);
    void *user_vaddr = page->vaddr;
    ASSERT(is_user_vaddr(user_vaddr));
    void *kernel_vaddr = palloc_get_page(PAL_USER | flags); //在用户page池里取一个空闲页
    if (!kernel_vaddr)                                      //如果没有空闲页了就驱逐一页使其空闲
    {
        frame_allocator_evict_page();
        kernel_vaddr = palloc_get_page(PAL_USER | flags);
        ASSERT(kernel_vaddr)
    }

    if (!install_page(user_vaddr, kernel_vaddr, writable)) //从用户虚拟地址向内核虚拟地址的映射，且将映射关系添加进页目录中
    {
        PANIC("Could not install user page %p", user_vaddr);
    }
    frame_map(kernel_vaddr, page, writable);
    lock_release(&frame_allocation_lock);
    memset(kernel_vaddr, 0, PGSIZE);

    return kernel_vaddr;
}
/*释放kernel_vaddr在frame_table对应的frame<-->page映射*/
void frame_allocator_free_user_page(void *kernel_vaddr, bool is_locked)
{
    if (!is_locked)
        lock_acquire(&frame_allocation_lock);

    palloc_free_page(kernel_vaddr); //释放kernel_vaddr处的页

    struct frame lookup;
    lookup.frame_addr = kernel_vaddr;

    struct hash_elem *e = hash_find(&frame_table, &lookup.hash_elem);
    if (!e) //如果frame_table里没有存放该kernel_vaddr对应的映射项那么报异常
        PANIC("Frame doesn't exist in frame table.");

    struct frame *f = hash_entry(e, struct frame, hash_elem); //获取frame

    f->page->page_status &= ~PAGE_IN_MEMORY; //

    tid_t thread_id = f->owner_id;
    struct thread *t = thread_find_thread(thread_id);
    if (!t)
        PANIC("Corruption of frame table");

    pagedir_clear_page(t->pagedir, f->page->vaddr); //在页目录中去除该kernel_vaddr与user_vaddr对应的映射
    frame_unmap(kernel_vaddr);                      //抹去frame_table的相关记录
    free(f);                                        //释放该临时变量

    if (!is_locked)
        lock_release(&frame_allocation_lock);
}
/*驱逐frame*/
static void *
frame_allocator_evict_page(void)
{
    struct frame *f = frame_allocator_choose_eviction_frame(); //选择被驱逐的frame

    frame_allocator_save_frame(f);                       //将驱逐的frame保存起来
    frame_allocator_free_user_page(f->frame_addr, true); //解除frame_table的相关项
}
static void
frame_allocator_save_frame(struct frame *f)
{
    tid_t thread_id = f->owner_id;
    struct thread *t = thread_find_thread(thread_id);
    if (!t)
        PANIC("Corruption of frame table");

    ASSERT(f->page);

    bool dirty_flag = pagedir_is_dirty(t->pagedir, f->page->vaddr);
    enum page_status status = f->page->page_status;

    if ((status & PAGE_MEMORY_MAPPED) && dirty_flag)
    {
        // struct page_mmap_info *mmap_info = (struct page_mmap_info *)f->page->aux;
        // struct mmap_mapping *m = mmap_get_mapping(&t->mmap_table, mmap_info->mapid);

        // mmap_write_back_data(m, f->frame_addr, mmap_info->offset, mmap_info->length);
    }
    else if (!(f->page->page_status & PAGE_LAZYEXEC))
    {
        struct swap_entry *s = swap_alloc();
        if (!s)
        {
            PANIC("error: No Swap Memory left!");
        }
        f->page->page_status |= PAGE_SWAP;
        f->page->page_status &= ~(PAGE_IN_MEMORY);
        f->page->aux = s;
        swap_save(s, (void *)f->frame_addr);
    }
}
void pin_frame(void *kaddr)
{
    lock_acquire(&frame_allocation_lock);
    struct frame *fr = find_frame_by_kaddr(kaddr);
    fr->unused_count = -1;
    lock_release(&frame_allocation_lock);
}
void unpin_frame(void *kaddr)
{
    lock_acquire(&frame_allocation_lock);
    struct frame *fr = find_frame_by_kaddr(kaddr);
    fr->unused_count = -1;
    lock_release(&frame_allocation_lock);
}

/**/
struct frame *
frame_allocator_choose_eviction_frame(void)
{
    struct hash_iterator i;
    struct thread *t;
    struct frame *eviction_candidate;
    int32_t least_used = 0;
    bool dirty_candidate = true;
    bool accessed_candidate = true;
    bool dirty;
    bool accessed;

    lock_acquire(&frame_table_lock);
    hash_first(&i, &frame_table);
    while (hash_next(&i))
    {
        struct frame *f = hash_entry(hash_cur(&i), struct frame, hash_elem);
        t = thread_find_thread(f->owner_id);
        dirty = pagedir_is_dirty(t->pagedir, f->frame_addr);
        accessed = pagedir_is_accessed(t->pagedir, f->frame_addr);
        if (f->unused_count < 0)
        {
            continue;
        }
        if (accessed)
        {
            if (!accessed_candidate)
            {
                f->unused_count = 0;
                break;
            }
        }
        else
            f->unused_count++;

        if (dirty)
        {
            if (!dirty_candidate)
            {
                f->unused_count = 0;
                break;
            }
        }
        else
            f->unused_count++;

        if (++f->unused_count > least_used) // && !(f->page->page_status & PAGE_LAZYEXEC)
        {
            eviction_candidate = f;
            dirty_candidate = dirty;
            accessed_candidate = accessed;
            least_used = f->unused_count;
        }
    }

    eviction_candidate->unused_count = 0;
    lock_release(&frame_table_lock);
    return eviction_candidate;
}