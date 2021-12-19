#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "vm/swap.h"
#include "vm/frame.h"
#define PAGE_NUM_SECTORS PGSIZE / BLOCK_SECTOR_SIZE
static struct block *swap_block;
static size_t swap_size;
static size_t max_pages;
static struct lock swap_lock;
static struct swap_entry *swap_table;
static size_t swap_table_size;

struct swap_entry *find_first_free_entry();

void swap_init()
{
  int i;
  swap_block = block_get_role(BLOCK_SWAP);
  swap_size = block_size(swap_block) * BLOCK_SECTOR_SIZE;
  max_pages = swap_size / PGSIZE;
  swap_table_size = max_pages * sizeof(struct swap_entry);
  swap_table = malloc(swap_table_size);
  if (!swap_table)
  {
    PANIC("error: no space swap");
  }
  lock_init(&swap_lock);
  for (i = 0; i < max_pages; i++)
  {
    swap_table[i].block = i * PAGE_NUM_SECTORS;
    swap_table[i].in_use = false;
  }
}

void swap_destroy()
{
  free(swap_table);
}

struct swap_entry *swap_alloc()
{
  lock_acquire(&swap_lock);
  struct swap_entry *entry = find_first_free_entry();
  if (!entry)
    PANIC("error: no space for swap alloc.");
  entry->in_use = true;
  lock_release(&swap_lock);
  return entry;
}

struct swap_entry *find_first_free_entry()
{
  struct swap_entry *entry;
  for (entry = swap_table; entry < swap_table + swap_table_size; entry++)
  {
    if (!entry->in_use)
      return entry;
  }
  return NULL;
}
void swap_free(struct swap_entry *swap_location)
{
  lock_acquire(&swap_lock);
  swap_location->in_use = false;
  lock_release(&swap_lock);
}

void swap_save(struct swap_entry *swap_location, void *physical_address)
{
  lock_acquire(&swap_lock);
  ASSERT(swap_location->in_use);
  unsigned ptr = physical_address;
  block_sector_t cnt;
  for (cnt = swap_location->block; cnt < swap_location->block + PAGE_NUM_SECTORS; cnt++)
  {
    block_write(swap_block, cnt, ptr);
    ptr += BLOCK_SECTOR_SIZE;
  }
  lock_release(&swap_lock);
}

void *swap_load(struct swap_entry *swap_location, struct page *page, void *kernel_vaddr)
{
  lock_acquire(&swap_lock);
  ASSERT(swap_location->in_use);
  unsigned page_sector = kernel_vaddr;
  block_sector_t cnt;
  for (cnt = swap_location->block; cnt < swap_location->block + PAGE_NUM_SECTORS; cnt++)
  {
    block_read(swap_block, cnt, page_sector);
    page_sector += BLOCK_SECTOR_SIZE;
  }
  lock_release(&swap_lock);
  return kernel_vaddr;
}
