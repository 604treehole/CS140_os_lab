#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/timer.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "userprog/syscall.h"
static thread_func start_process NO_RETURN;
static bool load(const char *cmdline, void (**eip)(void), void **esp);
void fd_table_destroy_func(struct hash_elem *e, void *aux UNUSED);
bool mmap_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
unsigned mmap_hash(const struct hash_elem *e, void *aux UNUSED);
void mmap_table_destroy_func(struct hash_elem *e, void *aux);
/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */

tid_t process_execute(const char *file_name)
{
  char *fn_copy, *proc_name;
  tid_t tid;
  struct thread *thr;
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL)
  {
    return TID_ERROR;
  }
  proc_name = palloc_get_page(0);
  if (proc_name == NULL)
  {
    palloc_free_page(fn_copy);
    return TID_ERROR;
  }
  strlcpy(fn_copy, file_name, PGSIZE);
  strlcpy(proc_name, file_name, PGSIZE);
  char *save_ptr;
  proc_name = strtok_r(proc_name, " ", &save_ptr);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(proc_name, PRI_DEFAULT, start_process, fn_copy);
  palloc_free_page(proc_name);
  if (tid == TID_ERROR)
    palloc_free_page(fn_copy);
  struct list ll = thread_current()->children;
  struct list_elem *e = NULL;

  for (e = list_begin(&ll); e != list_end(&ll); e = list_next(e))
  {
    struct thread *t = list_entry(e, struct process, elem);
    if (t->tid == tid)
      break;
  }
  if (!e)
    return TID_ERROR;
  struct process *proc = list_entry(e, struct process, elem);
  sema_down(&(proc->wait));
  int ret_tid = proc->child_started ? tid : -1;
  return ret_tid;
  // if ((proc->child_started) == 0)
  //   return TID_ERROR;
  // else
  //   return tid;
}
void push_argument(void **esp, int argc, int argv[])
{
  *esp = (int)*esp & 0xfffffffc;
  *esp = *esp - 4;
  *(int *)*esp = 0;
  for (int i = argc - 1; i >= 0; i--)
  {
    *esp -= 4;
    *(int *)*esp = argv[i];
  }
  *esp -= 4;
  *(int *)*esp = (int)*esp + 4; // char**
  *esp -= 4;
  *(int *)*esp = argc;
  *esp -= 4;
  *(int *)*esp = 0;
}
/* A thread function that loads a user process and starts it
   running. */
/*
  pintos -v -k -T 60 --bochs  --filesys-size=2 
  -p tests/userprog/exec-once -a exec-once 
  -p tests/userprog/child-simple -a   child-simple 
  -- -q  -f run exec-once 

  pintos -v -k -T 60 --bochs  --filesys-size=2 
  -p tests/userprog/args-many -a args-many -- -q  -f run 'args-many a b c d e f g h i j k l m n o p q r s t u v' < /dev/null 2> tests/userprog/args-many.errors > tests/userprog/args-many.output

  */
static void
start_process(void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;
  char *save_ptr;
  int argc = 0;
  int argv[50];
  char *cmd = malloc(strlen(file_name) + 1);
  char *free_cmd = cmd;
  strlcpy(cmd, file_name, strlen(file_name) + 1);
  file_name = strtok_r(file_name_, " ", &save_ptr);

  /* Initialize interrupt frame and load executable. */
  memset(&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load(file_name, &if_.eip, &if_.esp);

  // split args-many a b c d e f g h i j k l m n o p q r s t u v
  if (success)
  {
    for (char *left = strtok_r(cmd, " ", &save_ptr); left != NULL; left = strtok_r(NULL, " ", &save_ptr))
    {
      if_.esp -= (strlen(left) + 1);
      memcpy(if_.esp, left, strlen(left) + 1);
      argv[argc++] = (int)if_.esp;
    }
    push_argument(&if_.esp, argc, argv);
    thread_current()->proc->child_started = true;
    sema_up(&thread_current()->proc->wait);
    palloc_free_page(file_name_);
    free(free_cmd);
  }
  else /* If load failed, quit. */
  {
    thread_current()->proc->child_started = false;
    thread_current()->proc->self_alive = false;
    thread_current()->proc->exit_code = 0xeeee0eee;
    sema_up(&thread_current()->proc->wait);
    palloc_free_page(file_name_);
    free(free_cmd);
    thread_exit();
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit"
               :
               : "g"(&if_)
               : "memory");
  NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(tid_t child_tid UNUSED)
{
  // timer_msleep(1000);
  struct thread *cur = thread_current();
  struct list_elem *e;
  for (e = list_begin(&cur->children); e != list_end(&cur->children); e = list_next(e))
  {
    struct process *proc = list_entry(e, struct process, elem);
    if (proc->tid == child_tid)
    {
      if (proc->self_alive)
        sema_down(&(proc->wait));
      int exit_code = proc->exit_code;
      list_remove(e);
      free(proc);
      return exit_code;
    }
  }
  return -1;
}
/* Free the current process's resources. */
void process_exit(void)
{
  struct thread *cur = thread_current();
  struct list_elem *e;
  uint32_t *pd;
  if (lock_held_by_current_thread(&file_sys_lock))
  {
    lock_release(&file_sys_lock); //
    // printf("lock hold sys");
  }
  if (lock_held_by_current_thread(&cur->supplemental_page_table_lock))
  {
    lock_release(&cur->supplemental_page_table_lock); //
    // printf("lock holder page");
  }
  if (cur->running_procfile) // close the exec file
  {
    lock_acquire(&file_sys_lock);
    // file_allow_write(cur->running_procfile);
    file_close(cur->running_procfile);
    lock_release(&file_sys_lock);
  }
  if (cur->proc)
  {
    if (cur->proc->exit_code != 0xeeee0eee)
      printf("%s: exit(%d)\n", cur->name, cur->proc->exit_code);
    // debug_backtrace();
    hash_destroy(&cur->proc->fd_table, &fd_table_destroy_func); // close all files opened
    cur->proc->self_alive = false;

    if (cur->proc->parent_alive)
    {
      sema_up(&cur->proc->wait);
    }
    else
    {
      free(cur->proc);
    }
  }
  hash_destroy(&cur->mmap_table, mmap_table_destroy_func);
  hash_destroy(&cur->supplemental_page_table, userproc_supplemental_page_table_destroy_func);

  for (e = list_begin(&cur->children); e != list_end(&cur->children);)
  {
    struct process *proc = list_entry(e, struct process, elem);
    e = list_next(e);
    list_remove(&proc->elem);
    if (!proc->self_alive)
      free(proc);
    else
    {
      proc->parent_alive = false;
    }
  }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
  {

    /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
    cur->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void process_activate(void)
{
  struct thread *t = thread_current();

  /* Activate thread's page tables. */
  pagedir_activate(t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void **esp);
static bool validate_segment(const struct Elf32_Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable);
void stack_growing(struct thread *t, void *ptr)
{
  void *new_page_virtual = pg_round_down(ptr);
  struct page *p = create_in_memory_page_info(new_page_virtual, true);
  insert_page_info(&t->supplemental_page_table, p);
  void *page_ptr_frame = frame_allocator_get_user_page(p, PAL_ZERO, true);
  if (page_ptr_frame == NULL)
  {
    PANIC("error : stack growing null");
  }
}
/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char *file_name, void (**eip)(void), void **esp)
{
  struct thread *t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
  hash_init(&(t->supplemental_page_table), userproc_supplemental_page_table_hash, userproc_supplemental_page_table_less, NULL);
  hash_init(&t->mmap_table, mmap_hash, mmap_less, NULL);
  t->next_mmapid = 1;
  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create();
  if (t->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  lock_acquire(&file_sys_lock); // todo ???
  file = filesys_open(file_name);
  lock_release(&file_sys_lock);
  if (file == NULL)
  {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr || memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024)
  {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
  {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type)
    {
    case PT_NULL:
    case PT_NOTE:
    case PT_PHDR:
    case PT_STACK:
    default:
      /* Ignore this segment. */
      break;
    case PT_DYNAMIC:
    case PT_INTERP:
    case PT_SHLIB:
      goto done;
    case PT_LOAD:
      if (validate_segment(&phdr, file))
      {
        bool writable = (phdr.p_flags & PF_W) != 0;
        uint32_t file_page = phdr.p_offset & ~PGMASK;
        uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
        uint32_t page_offset = phdr.p_vaddr & PGMASK;
        uint32_t read_bytes, zero_bytes;
        if (phdr.p_filesz > 0)
        {
          /* Normal segment.
                     Read initial part from disk and zero the rest. */
          read_bytes = page_offset + phdr.p_filesz;
          zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
        }
        else
        {
          /* Entirely zero.
                     Don't read anything from disk. */
          read_bytes = 0;
          zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
        }
        if (!load_segment(file, file_page, (void *)mem_page,
                          read_bytes, zero_bytes, writable))
          goto done;
      }
      else
        goto done;
      break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp))
    goto done;

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;
  file_deny_write(file);

done:
  /* We arrive here whether the load is successful or not. */
  // file_close(file); when process exit close this file
  if (!success)
  {
    file_close(file);
    file = NULL;
  }
  t->running_procfile = file;
  return success;
}

/* load() helpers. */

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment(const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void *)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */

bool read_executable_page(struct file *file, size_t offset, void *kpage, size_t page_read_bytes, size_t page_zero_bytes)
{
  lock_acquire(&file_sys_lock);
  file_seek(file, offset);
  int bytes_read = file_read(file, kpage, page_read_bytes);
  lock_release(&file_sys_lock);
  if (bytes_read != (int)page_read_bytes)
    return false;
  memset((int)kpage + page_read_bytes, 0, page_zero_bytes);
  return true;
}
bool load_executable_page(struct file *file, off_t offset, void *upage,
                          size_t page_read_bytes, size_t page_zero_bytes, bool writable)
{
  struct hash *supplemental_page_table = &thread_current()->supplemental_page_table;
  struct page *p;
  if (page_read_bytes == PGSIZE)
  {
    struct page_filesys_info *filesys_info = malloc(sizeof(struct page_filesys_info));
    filesys_info->file = file;
    filesys_info->offset = offset;
    filesys_info->length = page_read_bytes;
    p = create_lazy_page_info(upage, filesys_info, writable);

    lock_acquire(&thread_current()->supplemental_page_table_lock);
    insert_page_info(supplemental_page_table, p);
    lock_release(&thread_current()->supplemental_page_table_lock);
  }
  else if (page_zero_bytes == PGSIZE)
  {
    p = create_lazy_zero_page_info(upage);
    lock_acquire(&thread_current()->supplemental_page_table_lock);
    insert_page_info(supplemental_page_table, p);
    lock_release(&thread_current()->supplemental_page_table_lock);
  }
  else
  {
    struct page_filesys_info *filesys_info = malloc(sizeof(struct page_filesys_info));
    filesys_info->file = file;
    filesys_info->offset = offset;
    filesys_info->length = page_read_bytes;
    p = create_lazy_page_info(upage, filesys_info, writable);
    lock_acquire(&thread_current()->supplemental_page_table_lock);
    insert_page_info(supplemental_page_table, p);
    lock_release(&thread_current()->supplemental_page_table_lock);
    uint8_t *kpage = frame_allocator_get_user_page(p, 0, true);
    if (!read_executable_page(file, offset, kpage, page_read_bytes, page_zero_bytes))
      return false;
    p->page_status &= ~PAGE_LAZYEXEC; // !! essential
    p->page_status |= PAGE_IN_MEMORY;
  }
  return true;
}

static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
             uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);
  unsigned offset = ofs;
  // file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
  {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;
    if (!load_executable_page(file, offset, upage, page_read_bytes, page_zero_bytes, writable))
      return false;
    /* Get a page of memory. */
    // uint8_t *kpage = palloc_get_page(PAL_USER);
    // if (kpage == NULL)
    //   return false;
    // /* Load this page. */
    // if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes)
    // {
    //   palloc_free_page(kpage);
    //   return false;
    // }
    // memset(kpage + page_read_bytes, 0, page_zero_bytes);

    // /* Add the page to the process's address space. */
    // if (!install_page(upage, kpage, writable))
    // {
    //   palloc_free_page(kpage);
    //   return false;
    // }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
    offset += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack(void **esp)
{
  uint8_t *kpage;
  bool success = false;

  // kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  // if (kpage != NULL)
  // {
  //   success = install_page(((uint8_t *)PHYS_BASE) - PGSIZE, kpage, true);
  //   if (success)
  //     *esp = PHYS_BASE;
  //   else
  //     palloc_free_page(kpage);
  // }
  void *user_vaddr = ((uint8_t *)PHYS_BASE) - PGSIZE;
  struct page *p = create_in_memory_page_info(user_vaddr, true);
  lock_acquire(&thread_current()->supplemental_page_table_lock);
  insert_page_info(&thread_current()->supplemental_page_table, p);
  lock_release(&thread_current()->supplemental_page_table_lock);
  kpage = frame_allocator_get_user_page(p, PAL_ZERO, true);
  if (kpage != NULL)
  {
    *esp = PHYS_BASE;
    success = true;
  }
  p->page_status |= PAGE_IN_MEMORY;
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool install_page(void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pagedir, upage) == NULL && pagedir_set_page(t->pagedir, upage, kpage, writable));
}

void fd_table_destroy_func(struct hash_elem *e, void *aux UNUSED)
{
  struct file_descriptor *descriptor = hash_entry(e, struct file_descriptor, hash_elem);
  ASSERT(descriptor->file != NULL);
  lock_acquire(&file_sys_lock);
  file_close(descriptor->file);
  lock_release(&file_sys_lock);
  free(descriptor);
}
struct file_descriptor *proc_get_fd_struct(int fd)
{
  if (fd < 2)
    return NULL;
  struct file_descriptor desc;
  desc.fd = fd;
  struct thread *t = thread_current();
  struct hash_elem *found_element = hash_find(&t->proc->fd_table, &desc.hash_elem);
  if (found_element == NULL)
    return NULL;
  struct file_descriptor *open_file_desc = hash_entry(found_element, struct file_descriptor, hash_elem);
  return open_file_desc;
}
unsigned mmap_hash(const struct hash_elem *e, void *aux UNUSED)
{
  const struct mmap_mapping *mapping = hash_entry(e, struct mmap_mapping, hash_elem);
  return hash_bytes(&mapping->mapid, sizeof(mapping->mapid));
}

bool mmap_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  const struct mmap_mapping *mapping_a = hash_entry(a, struct mmap_mapping, hash_elem);
  const struct mmap_mapping *mapping_b = hash_entry(b, struct mmap_mapping, hash_elem);
  return mapping_a->mapid < mapping_b->mapid;
}
struct mmap_mapping *mmap_get_mapping(struct hash *mmap_table, int mapid)
{
  struct mmap_mapping m;
  m.mapid = mapid;
  struct hash_elem *e = hash_find(mmap_table, &m.hash_elem);
  if (!e)
    return NULL;
  return hash_entry(e, struct mmap_mapping, hash_elem);
}
void mmap_write_back_data(struct mmap_mapping *mapping, void *source, size_t offset, size_t length)
{
  lock_acquire(&file_sys_lock);
  file_seek(mapping->file, offset);
  file_write(mapping->file, source, length);
  lock_release(&file_sys_lock);
}
void sys_munmap_inter(struct mmap_mapping *mapping, int destorying)
{
  lock_acquire(&file_sys_lock);
  off_t length = file_length(mapping->file);
  lock_release(&file_sys_lock);
  unsigned num_pages = length / PGSIZE;
  if (length % PGSIZE)
    num_pages++;
  struct hash *supt = &thread_current()->supplemental_page_table;
  unsigned i = 0;
  void *uaddr = mapping->uaddr;
  while (i < num_pages)
  {
    struct page *pageptr;
    if (supplemental_entry_exists(supt, uaddr, &pageptr))
    {
      if (pageptr->page_status & PAGE_IN_MEMORY)
      {
        struct page_mmap_info *mmap_info = (struct page_mmap_info *)pageptr->aux;
        void *kaddr = pagedir_get_page(thread_current()->pagedir, uaddr);
        if (pagedir_is_dirty(thread_current()->pagedir, pageptr->vaddr))
          mmap_write_back_data(mapping, kaddr, mmap_info->offset, mmap_info->length);
        frame_allocator_free_user_page(kaddr, false);
      }
      supplemental_remove_page_entry(supt, uaddr);
      uaddr += PGSIZE;
    }
    else
    {
      PANIC("mmap uaddr not exist");
    }
    i++;
  }
  if (!destorying)
  {
    struct mmap_mapping lookup;
    lookup.mapid = mapping->mapid;
    hash_delete(&thread_current()->mmap_table, &lookup.hash_elem);
  }
  lock_acquire(&file_sys_lock);
  file_close(mapping->file);
  lock_release(&file_sys_lock);
  free(mapping);
}
void mmap_table_destroy_func(struct hash_elem *e, void *aux)
{
  struct mmap_mapping *mapping = hash_entry(e, struct mmap_mapping, hash_elem);
  sys_munmap_inter(mapping, 1);
}