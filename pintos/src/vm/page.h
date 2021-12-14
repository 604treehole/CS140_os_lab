#ifndef VM_PAGE_H
#define VM_PAGE_H
#include <hash.h>
#include "threads/thread.h"
#include "vm/swap.h"
enum page_status
{
    PAGE_UNDEFINED = 0,
    PAGE_LAZYEXEC = 1 << 0,
    PAGE_ZERO = 1 << 1,
    PAGE_SWAP = 1 << 2,
    PAGE_MEMORY_MAPPED = 1 << 3,
    PAGE_IN_MEMORY = 1 << 4,
};
struct page_filesys_info
{
    struct file *file;
    size_t offset;
    size_t length;
};
struct page_mmap_info
{
    unsigned mapid;
    size_t offset;
    size_t length;
};
struct page
{
    struct hash_elem hash_elem;
    void *vaddr;
    void *kaddr;
    void *aux; /* */
    enum page_status page_status;
    bool writable;
};

int vm_load_page(struct hash *supplemental_page_table, void *uaddr);

struct page *create_lazy_page_info(void *vaddr, struct page_filesys_info *filesys_info, bool writable);
struct page *create_lazy_zero_page_info(void *vaddr);
struct page *create_in_memory_page_info(void *vaddr, bool writable);
struct page *create_mmap_page_info(void *vaddr, struct page_mmap_info *mmap_info);
struct page *create_swap_page(void *vaddr, struct swap_entry *swap_page);

void insert_page_info(struct hash *supplemental_page_table, struct page *page);

void set_page_in_memory(struct hash *supplemental_page_table, void *uaddr);
void set_page_not_in_memory(struct hash *supplemental_page_table, void *uaddr);

void pin_user_page(struct hash *supplemental_page_table, void *uaddr);
void unpin_user_page(struct hash *supplemental_page_table, void *uaddr);
bool supplemental_entry_exists(struct hash *supplemental_page_table, void *uaddr, struct page **entry);
bool supplemental_is_page_writable(struct hash *supplemental_page_table, void *uaddr);
void supplemental_remove_page_entry(struct hash *supplemental_page_table, void *uaddr);

unsigned userproc_supplemental_page_table_hash(const struct hash_elem *e, void *aux);
bool userproc_supplemental_page_table_less(const struct hash_elem *a, const struct hash_elem *b, void *aux);
void userproc_supplemental_page_table_destroy_func(struct hash_elem *e, void *aux);
#endif