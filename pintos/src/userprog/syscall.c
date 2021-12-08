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
bool valid_user_addr(unsigned *addr)
{
  return addr && addr < 0xc0000000;
  // && pagedir_get_page(thread_current()->pagedir, addr)
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int load_user_uaddr(const uint8_t *uaddr)
{
  int result;
  asm __volatile__("movl $1f, %0; movzbl %1, %0; 1:"
                   : "=&a"(result)
                   : "m"(*uaddr));
  return result;
}
unsigned int pop_stack(unsigned int **ptr)
{
  if (!valid_user_addr((unsigned *)(*ptr)) ||
      !valid_user_addr((unsigned *)(*ptr) + 1))
  {
    thread_current()->proc->exit_code = -1;
    thread_exit();
  }
  unsigned int top = (unsigned int)(**ptr);
  *ptr += 1;
  return top;
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
  if (!valid_user_addr((unsigned *)buf) || !valid_user_addr((unsigned *)(buf + size)))
  {
    thread_current()->proc->exit_code = -1;
    thread_exit();
  }
  void *buffer_page; // check stack grow
  lock_acquire(&thread_current()->supplemental_page_table_lock);
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
  lock_release(&thread_current()->supplemental_page_table_lock);
  load_user_uaddr(buf);
  if (fd == 0)
  {
    for (int i = 0; i < size; i++)
      buf[i] = input_getc();
    *eax = size;
  }
  else
  {
    struct file_descriptor *descriptor = proc_get_fd_struct(fd);
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
    lock_acquire(&file_sys_lock);
    struct file_descriptor *descriptor = proc_get_fd_struct(fd);
    if (descriptor)
    {
      struct file *f = descriptor->file;

      // printf("finish %d", fd);
      writed_size = (int)file_write(f, buf, size); // blocked
    }
    lock_release(&file_sys_lock);
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
  // int number = *(unsigned int *)(esp_addr);
  int number = pop_stack(&esp_addr);
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
  default:
    thread_current()->proc->exit_code = -1;
    thread_exit();
  }
}
