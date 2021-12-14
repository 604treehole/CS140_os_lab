#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "kernel/console.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/exception.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "vm/page.h"

static void syscall_handler(struct intr_frame *);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}
static int load_user_uaddr(const uint8_t *uaddr)
{
  int result;
  asm __volatile__("movl $1f, %0; movzbl %1, %0; 1:"
                   : "=&a"(result)
                   : "m"(*uaddr));
  return result;
}
bool valid_user_addr(unsigned *addr)
{
  return addr && addr < 0xc0000000 && -1 != load_user_uaddr(addr);
  // && pagedir_get_page(thread_current()->pagedir, addr)
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */

unsigned int pop_stack(unsigned int **ptr)
{
  if (!valid_user_addr((unsigned *)(*ptr)) ||
      !valid_user_addr((int)*ptr + 3))
  {
    thread_current()->proc->exit_code = -1;
    thread_exit();
  }
  unsigned int top = (unsigned int)(**ptr);
  *ptr += 1;
  return top;
}
void preload_and_pin_buf_addr(const void *buffer, size_t size)
{
  struct supplemental_page_table *tb = &thread_current()->supplemental_page_table;
  unsigned upage;
  for (upage = pg_round_down(buffer); upage < buffer + size; upage += PGSIZE)
  {
    vm_load_page(tb, upage);
    pin_user_page(tb, upage);
  }
}

void unpin_preloaded_buf_addr(const void *buffer, size_t size)
{
  struct supplemental_page_table *tb = &thread_current()->supplemental_page_table;
  void *upage;
  for (upage = pg_round_down(buffer); upage < buffer + size; upage += PGSIZE)
  {
    unpin_user_page(tb, upage);
  }
}

void sys_mmap(unsigned int *ptr, unsigned *eax)
{
  int fd = (int)pop_stack(&ptr);
  unsigned addr = pop_stack(&ptr);
  if (!(addr < 0xc0000000))
  {
    thread_current()->proc->exit_code = -1;
    thread_exit();
  }
  struct thread *cur = thread_current();
  if (addr == 0 || fd == 0 || fd == 1 || pg_ofs(addr) != 0)
  { //error mmap
    *eax = -1;
    return;
  }
  struct file_descriptor *dp = proc_get_fd_struct(fd);
  if (!dp)
  {
    *eax = -1;
    return;
  }
  lock_acquire(&file_sys_lock);
  struct file *file = file_reopen(dp->file);
  off_t length = file_length(file);
  lock_release(&file_sys_lock);
  if (length == 0)
  {
    *eax = -1;
    return;
  }
  unsigned num_pages = length / PGSIZE;
  if (length % PGSIZE)
    num_pages++;
  struct hash *supt = &thread_current()->supplemental_page_table;
  unsigned i = 0;
  while (i < num_pages)
  {
    if (supplemental_entry_exists(supt, addr + i * PGSIZE, NULL))
    {
      *eax = -1;
      return;
    }
    i++;
  }
  struct mmap_mapping *mapping = malloc(sizeof(struct mmap_mapping));
  ASSERT(mapping);
  mapping->mapid = cur->next_mmapid++;
  mapping->file = file;
  mapping->uaddr = addr;
  unsigned bytes_into_file = 0;
  void *uaddr = addr;
  for (i = 0; i < num_pages; ++i)
  {
    struct page_mmap_info *mmap_info = malloc(sizeof(struct page_mmap_info));
    if (!mmap_info)
    {
      thread_current()->proc->exit_code = -1;
      thread_exit();
    }
    mmap_info->offset = bytes_into_file;
    mmap_info->length = length - bytes_into_file < PGSIZE ? length - bytes_into_file : PGSIZE;
    mmap_info->mapid = mapping->mapid;

    lock_acquire(&cur->supplemental_page_table_lock);
    struct page *p = create_mmap_page_info(uaddr, mmap_info);
    insert_page_info(supt, p);
    lock_release(&cur->supplemental_page_table_lock);
    bytes_into_file += PGSIZE;
    uaddr += PGSIZE;
  }
  hash_insert(&cur->mmap_table, &mapping->hash_elem);
  *eax = mapping->mapid;
  return;
}

void sys_munmap(unsigned int *ptr)
{
  int mapid = (int)pop_stack(&ptr);
  struct hash *mmap_table = &thread_current()->mmap_table;
  struct mmap_mapping *mapping = mmap_get_mapping(mmap_table, mapid);
  if (!mapping)
    return;
  sys_munmap_inter(mapping, 0);
}
void sys_halt(struct intr_frame *f)
{
  shutdown_power_off();
}
bool sys_exit(unsigned int *ptr)
{
  int status = (int)pop_stack(&ptr);
  thread_current()->proc->exit_code = status;
  thread_exit();
  return true;
}

void sys_read(unsigned *ptr, unsigned *eax)
{
  int fd = (int)pop_stack(&ptr);
  char *buf = (char *)pop_stack(&ptr);
  unsigned size = pop_stack(&ptr);
  if (!(buf && buf < 0xc0000000) || !((buf + size) && (buf + size) < 0xc0000000)) // bad ptr
  {
    thread_current()->proc->exit_code = -1;
    thread_exit();
  }
  void *buffer_page; // check stack grow
  for (buffer_page = pg_round_down(buf); buffer_page <= buf + size; buffer_page += 4096)
  {
    if (is_in_stack(buffer_page, ptr))
    {
      struct page p;
      p.vaddr = buffer_page;
      struct hash_elem *e = hash_find(&thread_current()->supplemental_page_table, &p.hash_elem);
      if (!e)
      {
        stack_growing(thread_current(), buffer_page);
      }
    }
  }
  if (!supplemental_entry_exists(&thread_current()->supplemental_page_table, buf, NULL) || !supplemental_entry_exists(&thread_current()->supplemental_page_table, buf + size, NULL))
  {
    thread_current()->proc->exit_code = -1;
    thread_exit();
  }
  if (!supplemental_is_page_writable(&thread_current()->supplemental_page_table, buf))
  {
    thread_current()->proc->exit_code = -1;
    thread_exit();
  }
  if (fd == 0)
  {
    for (int i = 0; i < size; i++)
      buf[i] = input_getc();
    *eax = size;
  }
  else
  {
    struct file_descriptor *descriptor = proc_get_fd_struct(fd);
    preload_and_pin_buf_addr(buf, size);
    if (descriptor)
    {
      lock_acquire(&file_sys_lock);
      *eax = (int)file_read(descriptor->file, buf, size);
      lock_release(&file_sys_lock);
    }
    else
    {
      *eax = -1;
    }
    unpin_preloaded_buf_addr(buf, size);
  }
}

void sys_write(unsigned *ptr, unsigned *eax)
{
  int fd = (int)pop_stack(&ptr);
  const char *buf = (const char *)pop_stack(&ptr);
  unsigned size = pop_stack(&ptr);
  if (!valid_user_addr((unsigned *)buf) || !valid_user_addr((unsigned *)(buf + size)))
  {
    thread_current()->proc->exit_code = -1;
    thread_exit();
  }
  if (!supplemental_entry_exists(&thread_current()->supplemental_page_table, buf, NULL) || !supplemental_entry_exists(&thread_current()->supplemental_page_table, buf + size, NULL))
  {
    thread_current()->proc->exit_code = -1;
    thread_exit();
  }
  load_user_uaddr(buf);
  load_user_uaddr(buf + size);
  if (fd == 1)
  {
    putbuf(buf, size);
    *eax = size;
  }
  else
  {
    int writed_size = -1;
    struct file_descriptor *descriptor = proc_get_fd_struct(fd);
    if (descriptor)
    {
      struct file *f = descriptor->file;
      preload_and_pin_buf_addr(buf, size);
      lock_acquire(&file_sys_lock);
      writed_size = (int)file_write(f, buf, size); // blocked
      lock_release(&file_sys_lock);
      unpin_preloaded_buf_addr(buf, size);
    }
    *eax = writed_size;
  }
}
void sys_seek(unsigned *ptr)
{
  int fd = (int)pop_stack(&ptr);
  unsigned pos = pop_stack(&ptr);
  lock_acquire(&file_sys_lock);
  struct file_descriptor *descriptor = proc_get_fd_struct(fd);
  if (descriptor)
  {
    struct file *f = descriptor->file;
    file_seek(f, pos);
  }
  lock_release(&file_sys_lock);
}
void sys_tell(unsigned *ptr, unsigned *eax)
{
  int fd = (int)pop_stack(&ptr);
  unsigned pos = 0;
  lock_acquire(&file_sys_lock);
  struct file_descriptor *descriptor = proc_get_fd_struct(fd);
  if (descriptor)
  {
    struct file *f = descriptor->file;
    pos = (unsigned)file_tell(f);
  }
  lock_release(&file_sys_lock);
  *eax = pos;
}
void sys_wait(unsigned *ptr, unsigned *eax)
{
  int pid = (int)pop_stack(&ptr);
  int exit_code = process_wait(pid);
  *eax = exit_code;
}
static void
valid_buf_user(void *src, size_t bytes)
{
  int32_t value;
  size_t i;
  for (i = 0; i < bytes; i++)
  {
    value = load_user_uaddr(src + i);
    if (value == -1) // segfault or invalid memory access
    {
      thread_current()->proc->exit_code = -1;
      thread_exit();
    }
  }
}
void sys_exec(unsigned *ptr, unsigned *eax)
{
  const char *file = (const char *)pop_stack(&ptr);
  if (!valid_user_addr((unsigned *)file) || !valid_user_addr((unsigned *)file + 1))
  {
    thread_current()->proc->exit_code = -1;
    thread_exit();
  }
  tid_t t = process_execute(file);
  *eax = t;
}
void sys_create(unsigned *ptr, unsigned *eax)
{
  const char *file = (const char *)pop_stack(&ptr);
  unsigned initial_size = (unsigned)pop_stack(&ptr);

  // printf("create file %s\n", file);
  if (!valid_user_addr((unsigned *)file) || !valid_user_addr((unsigned *)file + 1))
  {
    thread_current()->proc->exit_code = -1;
    thread_exit();
  }
  load_user_uaddr(file);
  lock_acquire(&file_sys_lock);
  *eax = filesys_create(file, initial_size);
  lock_release(&file_sys_lock);
}
void sys_remove(unsigned *ptr, unsigned *eax)
{
  const char *file = (const char *)pop_stack(&ptr);
  if (!valid_user_addr((unsigned *)file) || !valid_user_addr((unsigned *)file + 1))
  {
    thread_current()->proc->exit_code = -1;
    thread_exit();
  }
  lock_acquire(&file_sys_lock);
  *eax = filesys_remove(file);
  lock_release(&file_sys_lock);
}
void sys_open(unsigned *ptr, unsigned *eax)
{
  const char *file = (const char *)pop_stack(&ptr);
  if (!valid_user_addr((unsigned *)file) || !valid_user_addr((unsigned *)file + 1))
  {
    thread_current()->proc->exit_code = -1;
    thread_exit();
  }
  load_user_uaddr(file);

  // printf("open %s \n", file);
  lock_acquire(&file_sys_lock);
  struct file *fptr = filesys_open(file);
  int fd = -1;
  if (fptr)
  {
    fd = thread_current()->proc->next_fd++;
    struct file_descriptor *fd_struct = (struct file_descriptor *)malloc(sizeof(struct file_descriptor));
    fd_struct->fd = fd;
    fd_struct->file = fptr;
    hash_insert(&thread_current()->proc->fd_table, &fd_struct->hash_elem);
  }
  lock_release(&file_sys_lock);
  *eax = fd;
}
void sys_filesize(unsigned *ptr, unsigned *eax)
{
  int fd = (int)pop_stack(&ptr);

  lock_acquire(&file_sys_lock);
  struct file_descriptor *descript = proc_get_fd_struct(fd);
  lock_release(&file_sys_lock);
  *eax = file_length(descript->file);
}
void sys_close(unsigned *ptr, unsigned *eax)
{
  int fd = (int)pop_stack(&ptr);

  lock_acquire(&file_sys_lock);
  struct file_descriptor *descript = proc_get_fd_struct(fd);
  if (descript)
  {
    struct file_descriptor dd;
    dd.fd = descript->fd;
    file_close(descript->file);
    hash_delete(&thread_current()->proc->fd_table, &dd.hash_elem);
    free(descript);
  }
  lock_release(&file_sys_lock);
}
static void
syscall_handler(struct intr_frame *f UNUSED)
{
  unsigned *esp_addr = (unsigned *)f->esp;
  unsigned *eax_addr = (unsigned *)&f->eax;
  thread_current()->current_esp = f->esp;
  int number = pop_stack(&esp_addr);
  // printf("%s tid:%d syscall_id %d\n", thread_current()->name, thread_current()->tid, number);
  switch (number)
  {
  case SYS_HALT:
    sys_halt(f);
    break;
  case SYS_EXIT:
    sys_exit(esp_addr);
    break;
  case SYS_EXEC:
    sys_exec(esp_addr, eax_addr);
    break;
  case SYS_WAIT:
    sys_wait(esp_addr, eax_addr);
    break;
  case SYS_CREATE:
    sys_create(esp_addr, eax_addr);
    break;
  case SYS_REMOVE:
    sys_remove(esp_addr, eax_addr);
    break;
  case SYS_OPEN:
    sys_open(esp_addr, eax_addr);
    break;
  case SYS_FILESIZE:
    sys_filesize(esp_addr, eax_addr);
    break;
  case SYS_READ:
    sys_read(esp_addr, eax_addr);
    break;
  case SYS_WRITE:
    sys_write(esp_addr, eax_addr);
    break;
  case SYS_SEEK:
    sys_seek(esp_addr);
    break;
  case SYS_TELL:
    sys_tell(esp_addr, eax_addr);
    break;
  case SYS_CLOSE:
    sys_close(esp_addr, eax_addr);
    break;
  case SYS_MMAP:
    sys_mmap(esp_addr, eax_addr);
    break;
  case SYS_MUNMAP:
    sys_munmap(esp_addr);
    break;
  default:
    thread_current()->proc->exit_code = -1;
    thread_exit();
  }

  // printf("%s tid:%d syscall_id %d finished\n", thread_current()->name, thread_current()->tid, number);
}
