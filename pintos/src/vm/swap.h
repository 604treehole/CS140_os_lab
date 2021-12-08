#ifndef VM_SWAP_H
#define VM_SWAP_H
#include <stdbool.h>
#include "devices/block.h"
#include "vm/page.h"
struct swap_entry
{
    block_sector_t block;
    bool in_use;
};
void swap_init();
void swap_destroy();
struct swap_entry *swap_alloc();
void swap_free(struct swap_entry *swap_location);
void swap_save(struct swap_entry *swap_location, void *physical_address);
void *swap_load(struct swap_entry *swap_location, struct page *page, void *kernel_vaddr);

#endif VM_SWAP_H