#include <debug.h>
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "devices/timer.h"
static struct page *userproc_supplemental_get_page_info(struct hash *supplemental_page_table, void *vaddr);
static void free_user_page(void *upage);

struct page *create_lazy_page_info(void *vaddr, struct page_filesys_info *filesys_info, bool writable)
{
    struct page *page_info = malloc(sizeof(struct page));
    if (page_info)
    {
        page_info->page_status = PAGE_LAZYEXEC;
        page_info->aux = filesys_info;
        page_info->writable = writable;
        page_info->vaddr = vaddr;
    }
    return page_info;
}
struct page *create_lazy_zero_page_info(void *vaddr)
{
    struct page *page_info = malloc(sizeof(struct page));
    if (page_info)
    {
        page_info->page_status = PAGE_ZERO;
        page_info->aux = NULL;
        page_info->writable = true;
        page_info->vaddr = vaddr;
    }
    return page_info;
}
struct page *create_mmap_page_info(void *vaddr, struct page_mmap_info *mmap_info)
{
    struct page *page_info = malloc(sizeof(struct page));
    if (page_info)
    {
        page_info->page_status = PAGE_MEMORY_MAPPED;
        page_info->aux = mmap_info;
        page_info->vaddr = vaddr;
    }
    return page_info;
}

struct page *create_swap_page(void *vaddr, struct swap_entry *swap_page)
{
    struct page *page_info = malloc(sizeof(struct page));
    if (page_info)
    {
        page_info->page_status = PAGE_SWAP;
        page_info->aux = (void *)swap_page;
        page_info->writable = false;
        page_info->vaddr = vaddr;
    }
    return page_info;
}

struct page *create_in_memory_page_info(void *vaddr, bool writable)
{
    struct page *page_info = malloc(sizeof(struct page));
    if (page_info)
    {
        page_info->page_status = PAGE_IN_MEMORY;
        page_info->aux = NULL;
        page_info->writable = writable;
        page_info->vaddr = vaddr;
    }
    return page_info;
}
void insert_page_info(struct hash *supplemental_page_table,
                      struct page *page)
{
    hash_insert(supplemental_page_table, &page->hash_elem);
}
static void
free_user_page(void *upage)
{
    struct thread *t = thread_current();
    void *kpage = pagedir_get_page(t->pagedir, upage);

    frame_allocator_free_user_page(kpage, false);
}
static struct page *
userproc_supplemental_get_page_info(struct hash *supplemental_page_table, void *vaddr)
{
    void *paddr = pg_round_down(vaddr);
    struct hash_iterator it;
    hash_first(&it, supplemental_page_table);
    while (hash_next(&it))
    {
        struct page *p = hash_entry(hash_cur(&it), struct page, hash_elem);
        if (p->vaddr == paddr)
            return p;
    }
    return NULL;
    // struct page p;
    // p.vaddr = pg_round_down(vaddr);
    // struct hash_elem *e = hash_find(supplemental_page_table, &p.hash_elem);
    // if (e == NULL)
    //     return NULL;
    // return hash_entry(e, struct page, hash_elem);
}
void pin_user_page(struct hash *supplemental_page_table, void *uaddr)
{
    struct page *p = userproc_supplemental_get_page_info(supplemental_page_table, uaddr);
    pin_frame(p->kaddr);
}
void unpin_user_page(struct hash *supplemental_page_table, void *uaddr)
{
    struct page *p = userproc_supplemental_get_page_info(supplemental_page_table, uaddr);
    unpin_frame(p->kaddr);
}
int lazy_load_file(struct page *page)
{
    struct page_filesys_info *filesys_info = (struct page_filesys_info *)page->aux;
    struct file *file = filesys_info->file;
    size_t ofs = filesys_info->offset;
    void *kpage = frame_allocator_get_user_page(page, 0, page->writable);
    // printf("load lazy\n");
    if (!read_executable_page(file, ofs, kpage, filesys_info->length, 0))
        return 0;
    page->page_status |= PAGE_IN_MEMORY;
    return 1;
}

int zero_page(struct page *page)
{
    frame_allocator_get_user_page(page, PAL_ZERO, true);
    page->page_status &= ~PAGE_ZERO;
    page->page_status |= PAGE_IN_MEMORY;
    return 1;
}
int swap_page(struct page *page)
{ //todo
    struct swap_entry *swap_info = (struct swap_entry *)page->aux;
    // printf("swaping     ");
    void *kernel_vaddr = frame_allocator_get_user_page(page, 0, true);
    // printf("get kaddr       ");
    swap_load(swap_info, page, kernel_vaddr);
    // printf("load from swap      ");
    swap_free(swap_info);
    // printf("free swap\n");
    page->page_status &= ~PAGE_SWAP;
    page->page_status |= PAGE_IN_MEMORY;
    return 1;
}
int mmap_page(struct page *page)
{
    struct page_mmap_info *mmap_info = (struct page_mmap_info *)page->aux;
    void *kpage = frame_allocator_get_user_page(page, PAL_ZERO, true);
    struct mmap_mapping *m = mmap_get_mapping(&thread_current()->mmap_table, mmap_info->mapid);
    if (!m)
    {
        frame_allocator_free_user_page(kpage, false);
        thread_current()->proc->exit_code = -1;
        thread_exit();
    }
    struct file *file = m->file;
    size_t ofs = mmap_info->offset;
    size_t length = mmap_info->length;
    bool holding = false;
    lock_acquire(&file_sys_lock);
    file_seek(file, ofs);
    int bytes_read = file_read(file, kpage, length);
    lock_release(&file_sys_lock);
    if (bytes_read != length)
    {
        frame_allocator_free_user_page(kpage, false);
        thread_current()->proc->exit_code = -1;
        thread_exit();
    }
    page->page_status |= PAGE_IN_MEMORY;
    return true;
}
int vm_load_page(struct hash *supplemental_page_table, void *uaddr)
{
    struct page *p = userproc_supplemental_get_page_info(supplemental_page_table, uaddr);
    // printf("load status %d\n", p->page_status);
    if (p->page_status & PAGE_IN_MEMORY)
    {
        return 1;
    }
    else if (p->page_status & PAGE_SWAP)
    {
        if (!swap_page(p))
            return 0;
    }
    else if (p->page_status & PAGE_ZERO)
    {
        if (!zero_page(p))
            return 0;
    }
    else if (p->page_status & PAGE_LAZYEXEC)
    {
        if (!lazy_load_file(p))
            return 0;
    }
    else if (p->page_status & PAGE_MEMORY_MAPPED)
    {
        if (!mmap_page(p))
            return 0;
    }
    return 1;
}
bool supplemental_entry_exists(struct hash *supplemental_page_table, void *uaddr, struct page **entry)
{
    struct page *p = userproc_supplemental_get_page_info(supplemental_page_table, uaddr);
    if (!p)
        return false;
    if (entry)
        *entry = p;
    return true;
}

void supplemental_remove_page_entry(struct hash *supplemental_page_table, void *uaddr)
{
    struct page p;
    p.vaddr = pg_round_down(uaddr);

    struct page *page_info = NULL;
    if (!supplemental_entry_exists(supplemental_page_table, uaddr, &page_info))
        return;

    hash_delete(supplemental_page_table, &p.hash_elem);
    free(page_info);
}

bool supplemental_is_page_writable(struct hash *supplemental_page_table, void *uaddr)
{
    struct page *p = userproc_supplemental_get_page_info(supplemental_page_table, uaddr);
    if (!p)
        PANIC("Error: userproc_supplemental_is_page_writable", p);

    return p->writable;
}

unsigned
userproc_supplemental_page_table_hash(const struct hash_elem *e, void *aux UNUSED)
{
    const struct page *p = hash_entry(e, struct page, hash_elem);

    return hash_bytes(&p->vaddr, sizeof(p->vaddr));
}

bool userproc_supplemental_page_table_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    const struct page *page_a = hash_entry(a, struct page, hash_elem);
    const struct page *page_b = hash_entry(b, struct page, hash_elem);
    return page_a->vaddr < page_b->vaddr;
}

void userproc_supplemental_page_table_destroy_func(struct hash_elem *e, void *aux UNUSED)
{
    struct page *page = hash_entry(e, struct page, hash_elem);
    page->kaddr = NULL;
    if (page->page_status & PAGE_IN_MEMORY)
    {
        if (page->vaddr)
            free_user_page(page->vaddr);
    }
    if (page->aux)
    {
        if (page->page_status & PAGE_LAZYEXEC || (page->page_status & PAGE_MEMORY_MAPPED))
        {
            free(page->aux);
            page->aux = NULL;
        }
        if (page->page_status & PAGE_SWAP)
        {
            swap_free(page->aux);
            page->aux = NULL;
        }
    }
    free(page);
}
