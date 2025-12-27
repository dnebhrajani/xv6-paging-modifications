#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "proc.h"
#include "vm.h"
#include "memstat.h"

uint64
sys_exit(void)
{
  int n;
  argint(0, &n);
  kexit(n);
  return 0;  // not reached
}

uint64
sys_getpid(void)
{
  return myproc()->pid;
}

uint64
sys_fork(void)
{
  return kfork();
}

uint64
sys_wait(void)
{
  uint64 p;
  argaddr(0, &p);
  return kwait(p);
}

uint64
sys_sbrk(void)
{
  int size_delta, alloc_type;
  uint64 old_size;

  argint(0, &size_delta);
  argint(1, &alloc_type);
  old_size = myproc()->sz;

  // Check allocation type
  if(alloc_type == SBRK_EAGER || size_delta < 0) {
    if(growproc(size_delta) < 0)
      return -1;
  } else {
    // Lazy mode
    if(old_size + size_delta < old_size)
      return -1;
    myproc()->sz += size_delta;
  }
  
  return old_size;
}

uint64
sys_pause(void)
{
  int n;
  uint ticks0;

  argint(0, &n);
  if(n < 0)
    n = 0;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(killed(myproc())){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

uint64
sys_kill(void)
{
  int pid;

  argint(0, &pid);
  return kkill(pid);
}

// return how many clock tick interrupts have occurred
// since start.
uint64
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

uint64
sys_memstat(void)
{
  uint64 user_addr;
  struct proc *currproc = myproc();
  struct proc_mem_stat mem_stat;
  int entry_count = 0;
  
  argaddr(0, &user_addr);
  
  mem_stat.pid = currproc->pid;
  mem_stat.next_fifo_seq = currproc->next_seq;
  mem_stat.num_swapped_pages = 0;
  mem_stat.num_resident_pages = 0;
  mem_stat.num_pages_total = PGROUNDUP(currproc->sz) / PGSIZE;
  
  // Collect page info
  for(int idx = 0; idx < MAX_RESIDENT_PAGES && entry_count < MAX_PAGES_INFO; idx++) {
    if(currproc->resident_pages[idx].valid) {
      if(!currproc->resident_pages[idx].in_swap) {
        mem_stat.num_resident_pages++;
        mem_stat.pages[entry_count].state = RESIDENT;
        mem_stat.pages[entry_count].swap_slot = -1;        
      } else {
        mem_stat.num_swapped_pages++;
        mem_stat.pages[entry_count].state = SWAPPED;
        mem_stat.pages[entry_count].swap_slot = currproc->resident_pages[idx].swap_slot;
      }
      mem_stat.pages[entry_count].va = currproc->resident_pages[idx].va;
      mem_stat.pages[entry_count].seq = currproc->resident_pages[idx].seq;
      mem_stat.pages[entry_count].is_dirty = currproc->resident_pages[idx].dirty;
      entry_count++;
    }
  }
  
  // Fill unmapped pages
  for(; entry_count < MAX_PAGES_INFO && entry_count < mem_stat.num_pages_total; entry_count++) {
    mem_stat.pages[entry_count].va = entry_count * PGSIZE;
    mem_stat.pages[entry_count].state = UNMAPPED;
    mem_stat.pages[entry_count].is_dirty = 0;
    mem_stat.pages[entry_count].seq = 0;
    mem_stat.pages[entry_count].swap_slot = -1;
  }
  
  if(copyout(currproc->pagetable, user_addr, (char*)&mem_stat, sizeof(mem_stat)) < 0)
    return -1;
  
  return 0;
}
