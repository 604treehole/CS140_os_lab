#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "kernel/console.h"

static void syscall_handler(struct intr_frame *);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}
bool valid_user_addr(unsigned *addr)
{
  return addr && addr < 0xc0000000 && pagedir_get_page(thread_current()->pagedir, addr);
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

bool sys_write(unsigned *ptr, unsigned *eax)
{
  int fd = (int)pop_stack(&ptr);
  const char *buf = (const char *)pop_stack(&ptr);
  unsigned size = pop_stack(&ptr);
  if (!valid_user_addr((unsigned *)buf) || !valid_user_addr((unsigned *)(buf + size)))
    return false;
  if (fd == 1)
  {
    putbuf(buf, size);
    *eax = size;
  }
  else
  {
    printf("System call write.\n");
  }
  return true;
}
void sys_close(unsigned *ptr, unsigned *eax)
{
  return true;
}
static void
syscall_handler(struct intr_frame *f UNUSED)
{
  unsigned *esp_addr = (unsigned *)f->esp;
  unsigned *eax_addr = (unsigned *)f->eax;
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
    printf("System call exec.\n");
    break;
  case SYS_WAIT:
    printf("System call wait.\n");
    break;
  case SYS_CREATE:
    printf("System call create.\n");
    break;
  case SYS_REMOVE:
    printf("System call remove.\n");
    break;
  case SYS_OPEN:
    printf("System call open.\n");
    break;
  case SYS_FILESIZE:
    printf("System call filesize.\n");
    break;
  case SYS_READ:
    printf("System call read.\n");
    break;
  case SYS_WRITE:
    sys_write(esp_addr, eax_addr);
    break;
  case SYS_SEEK:
    printf("System call seek.\n");
    break;
  case SYS_TELL:
    printf("System call tell.\n");
    break;
  case SYS_CLOSE:
    printf("System call clsoe.\n");
    break;

  default:
    thread_current()->proc->exit_code = -1;
    thread_exit();
  }
}
