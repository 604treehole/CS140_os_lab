#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "hash.h"
#include "threads/synch.h"
typedef int tid_t;
struct lock file_sys_lock;
struct file_descriptor
{
    int fd;
    struct file *file;
    struct hash_elem hash_elem;
};
struct process
{
    tid_t tid;
    int exit_code;
    bool child_started;
    bool self_alive;
    bool parent_alive;
    int next_fd;
    struct hash fd_table;
    struct list_elem elem;
    struct semaphore wait; // q
};
bool install_page(void *upage, void *kpage, bool writable);
void stack_growing(struct thread *t, void *ptr);
bool read_executable_page(struct file *file, size_t offset, void *kpage, size_t page_read_bytes, size_t page_zero_bytes);
tid_t process_execute(const char *file_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(void);
struct file_descriptor *proc_get_fd_struct(int fd);
#endif /* userprog/process.h */
