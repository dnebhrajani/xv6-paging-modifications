#include "param.h"
#include "types.h"
#include "memlayout.h"
#include "elf.h"
#include "riscv.h"
#include "defs.h"
#include "spinlock.h"
#include "proc.h"
#include "fs.h"
#include "sleeplock.h"
#include "file.h"
#include "stat.h"

/*
 * the kernel's page table.
 */
pagetable_t kernel_pagetable;

extern char etext[];  // kernel.ld sets this to end of kernel code.

extern char trampoline[]; // trampoline.S

// Make a direct-map page table for the kernel.
pagetable_t
kvmmake(void)
{
  pagetable_t kpgtbl;

  kpgtbl = (pagetable_t) kalloc();
  memset(kpgtbl, 0, PGSIZE);

  // uart registers
  kvmmap(kpgtbl, UART0, UART0, PGSIZE, PTE_R | PTE_W);

  // virtio mmio disk interface
  kvmmap(kpgtbl, VIRTIO0, VIRTIO0, PGSIZE, PTE_R | PTE_W);

  // PLIC
  kvmmap(kpgtbl, PLIC, PLIC, 0x4000000, PTE_R | PTE_W);

  // map kernel text executable and read-only.
  kvmmap(kpgtbl, KERNBASE, KERNBASE, (uint64)etext-KERNBASE, PTE_R | PTE_X);

  // map kernel data and the physical RAM we'll make use of.
  kvmmap(kpgtbl, (uint64)etext, (uint64)etext, PHYSTOP-(uint64)etext, PTE_R | PTE_W);

  // map the trampoline for trap entry/exit to
  // the highest virtual address in the kernel.
  kvmmap(kpgtbl, TRAMPOLINE, (uint64)trampoline, PGSIZE, PTE_R | PTE_X);

  // allocate and map a kernel stack for each process.
  proc_mapstacks(kpgtbl);
  
  return kpgtbl;
}

// add a mapping to the kernel page table.
// only used when booting.
// does not flush TLB or enable paging.

void
kvmmap(pagetable_t kpgtbl, uint64 va, uint64 pa, uint64 sz, int perm)
{
  if(mappages(kpgtbl, va, sz, pa, perm) != 0)
    panic("kvmmap");
}

// Initialize the kernel_pagetable, shared by all CPUs.
void
kvminit(void)
{
  kernel_pagetable = kvmmake();
}

// Switch the current CPU's h/w page table register to
// the kernel's page table, and enable paging.
void
kvminithart()
{
  // wait for any previous writes to the page table memory to finish.
  sfence_vma();

  w_satp(MAKE_SATP(kernel_pagetable));

  // flush stale entries from the TLB.
  sfence_vma();
}

// Return the address of the PTE in page table pagetable
// that corresponds to virtual address va.  If alloc!=0,
// create any required page-table pages.
//
// The risc-v Sv39 scheme has three levels of page-table
// pages. A page-table page contains 512 64-bit PTEs.
// A 64-bit virtual address is split into five fields:
//   39..63 -- must be zero.
//   30..38 -- 9 bits of level-2 index.
//   21..29 -- 9 bits of level-1 index.
//   12..20 -- 9 bits of level-0 index.
//    0..11 -- 12 bits of byte offset within the page.
pte_t *
walk(pagetable_t pagetable, uint64 va, int alloc)
{
  if(va >= MAXVA)
    panic("walk");

  for(int level = 2; level > 0; level--) {
    pte_t *pte = &pagetable[PX(level, va)];
    if(*pte & PTE_V) {
      pagetable = (pagetable_t)PTE2PA(*pte);
    } else {
      if(!alloc || (pagetable = (pde_t*)kalloc()) == 0)
        return 0;
      memset(pagetable, 0, PGSIZE);
      *pte = PA2PTE(pagetable) | PTE_V;
    }
  }
  return &pagetable[PX(0, va)];
}

// Look up a virtual address, return the physical address,
// or 0 if not mapped.
// Can only be used to look up user pages.
uint64
walkaddr(pagetable_t pagetable, uint64 va)
{
  pte_t *pte;
  uint64 pa;

  if(va >= MAXVA)
    return 0;

  pte = walk(pagetable, va, 0);
  if(pte == 0)
    return 0;
  if((*pte & PTE_V) == 0)
    return 0;
  if((*pte & PTE_U) == 0)
    return 0;
  pa = PTE2PA(*pte);
  return pa;
}

// Create PTEs for virtual addresses starting at va that refer to
// physical addresses starting at pa.
// va and size MUST be page-aligned.
// Returns 0 on success, -1 if walk() couldn't
// allocate a needed page-table page.
int
mappages(pagetable_t pagetable, uint64 va, uint64 size, uint64 pa, int perm)
{
  uint64 a, last;
  pte_t *pte;

  if((va % PGSIZE) != 0)
    panic("mappages: va not aligned");

  if((size % PGSIZE) != 0)
    panic("mappages: size not aligned");

  if(size == 0)
    panic("mappages: size");
  
  a = va;
  last = va + size - PGSIZE;
  for(;;){
    if((pte = walk(pagetable, a, 1)) == 0)
      return -1;
    if(*pte & PTE_V)
      panic("mappages: remap");
    *pte = PA2PTE(pa) | perm | PTE_V;
    if(a == last)
      break;
    a += PGSIZE;
    pa += PGSIZE;
  }
  return 0;
}

// create an empty user page table.
// returns 0 if out of memory.
pagetable_t
uvmcreate()
{
  pagetable_t pagetable;
  pagetable = (pagetable_t) kalloc();
  if(pagetable == 0)
    return 0;
  memset(pagetable, 0, PGSIZE);
  return pagetable;
}

// Remove npages of mappings starting from va. va must be
// page-aligned. It's OK if the mappings don't exist.
// Optionally free the physical memory.
void
uvmunmap(pagetable_t pagetable, uint64 va, uint64 npages, int do_free)
{
  uint64 a;
  pte_t *pte;

  if((va % PGSIZE) != 0)
    panic("uvmunmap: not aligned");

  for(a = va; a < va + npages*PGSIZE; a += PGSIZE){
    if((pte = walk(pagetable, a, 0)) == 0) // leaf page table entry allocated?
      continue;   
    if((*pte & PTE_V) == 0)  // has physical page been allocated?
      continue;
    if(do_free){
      uint64 pa = PTE2PA(*pte);
      kfree((void*)pa);
    }
    *pte = 0;
  }
}

// Allocate PTEs and physical memory to grow a process from oldsz to
// newsz, which need not be page aligned.  Returns new size or 0 on error.
uint64
uvmalloc(pagetable_t pagetable, uint64 oldsz, uint64 newsz, int xperm)
{
  char *mem;
  uint64 a;

  if(newsz < oldsz)
    return oldsz;

  oldsz = PGROUNDUP(oldsz);
  for(a = oldsz; a < newsz; a += PGSIZE){
    mem = kalloc();
    if(mem == 0){
      uvmdealloc(pagetable, a, oldsz);
      return 0;
    }
    memset(mem, 0, PGSIZE);
    if(mappages(pagetable, a, PGSIZE, (uint64)mem, PTE_R|PTE_U|xperm) != 0){
      kfree(mem);
      uvmdealloc(pagetable, a, oldsz);
      return 0;
    }
  }
  return newsz;
}

// Deallocate user pages to bring the process size from oldsz to
// newsz.  oldsz and newsz need not be page-aligned, nor does newsz
// need to be less than oldsz.  oldsz can be larger than the actual
// process size.  Returns the new process size.
uint64
uvmdealloc(pagetable_t pagetable, uint64 oldsz, uint64 newsz)
{
  if(newsz >= oldsz)
    return oldsz;

  if(PGROUNDUP(newsz) < PGROUNDUP(oldsz)){
    int npages = (PGROUNDUP(oldsz) - PGROUNDUP(newsz)) / PGSIZE;
    uvmunmap(pagetable, PGROUNDUP(newsz), npages, 1);
  }

  return newsz;
}

// Recursively free page-table pages.
// All leaf mappings must already have been removed.
void
freewalk(pagetable_t pagetable)
{
  // there are 2^9 = 512 PTEs in a page table.
  for(int i = 0; i < 512; i++){
    pte_t pte = pagetable[i];
    if((pte & PTE_V) && (pte & (PTE_R|PTE_W|PTE_X)) == 0){
      // this PTE points to a lower-level page table.
      uint64 child = PTE2PA(pte);
      freewalk((pagetable_t)child);
      pagetable[i] = 0;
    } else if(pte & PTE_V){
      panic("freewalk: leaf");
    }
  }
  kfree((void*)pagetable);
}

// Free user memory pages,
// then free page-table pages.
void
uvmfree(pagetable_t pagetable, uint64 sz)
{
  if(sz > 0)
    uvmunmap(pagetable, 0, PGROUNDUP(sz)/PGSIZE, 1);
  freewalk(pagetable);
}

// Given a parent process's page table, copy
// its memory into a child's page table.
// Copies both the page table and the
// physical memory.
// returns 0 on success, -1 on failure.
// frees any allocated pages on failure.
int
uvmcopy(pagetable_t old, pagetable_t new, uint64 sz, struct proc *np)
{
  pte_t *pte;
  uint64 pa, i;
  uint flags;
  char *mem;

  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walk(old, i, 0)) == 0)
      continue;   // page table entry hasn't been allocated
    if((*pte & PTE_V) == 0)
      continue;   // physical page hasn't been allocated
    pa = PTE2PA(*pte);
    flags = PTE_FLAGS(*pte);
    if((mem = kalloc()) == 0)
      goto err;
    memmove(mem, (char*)pa, PGSIZE);
    if(mappages(new, i, PGSIZE, (uint64)mem, flags) != 0){
      kfree(mem);
      goto err;
    }
  }
  return 0;

 err:
  uvmunmap(new, 0, i / PGSIZE, 1);
  return -1;
}

// mark a PTE invalid for user access.
// used by exec for the user stack guard page.
void
uvmclear(pagetable_t pagetable, uint64 va)
{
  pte_t *pte;
  
  pte = walk(pagetable, va, 0);
  if(pte == 0)
    panic("uvmclear");
  *pte &= ~PTE_U;
}

// Copy from kernel to user.
// Copy len bytes from src to virtual address dstva in a given page table.
// Return 0 on success, -1 on error.
int
copyout(pagetable_t pagetable, uint64 dstva, char *src, uint64 len)
{
  uint64 n, va0, pa0;
  pte_t *pte;

  while(len > 0){
    va0 = PGROUNDDOWN(dstva);
    if(va0 >= MAXVA)
      return -1;
  
    pa0 = walkaddr(pagetable, va0);
    if(pa0 == 0) {
      if((pa0 = vmfault(pagetable, va0, 0, 0)) == 0) {
        return -1;
      }
    }

    pte = walk(pagetable, va0, 0);
    // forbid copyout over read-only user text pages.
    if((*pte & PTE_W) == 0)
      return -1;
      
    n = PGSIZE - (dstva - va0);
    if(n > len)
      n = len;
    memmove((void *)(pa0 + (dstva - va0)), src, n);

    len -= n;
    src += n;
    dstva = va0 + PGSIZE;
  }
  return 0;
}

// Copy from user to kernel.
// Copy len bytes to dst from virtual address srcva in a given page table.
// Return 0 on success, -1 on error.
int
copyin(pagetable_t pagetable, char *dst, uint64 srcva, uint64 len)
{
  uint64 n, va0, pa0;

  while(len > 0){
    va0 = PGROUNDDOWN(srcva);
    pa0 = walkaddr(pagetable, va0);
    if(pa0 == 0) {
      if((pa0 = vmfault(pagetable, va0, 0, 0)) == 0) {
        return -1;
      }
    }
    n = PGSIZE - (srcva - va0);
    if(n > len)
      n = len;
    memmove(dst, (void *)(pa0 + (srcva - va0)), n);

    len -= n;
    dst += n;
    srcva = va0 + PGSIZE;
  }
  return 0;
}

// Copy a null-terminated string from user to kernel.
// Copy bytes to dst from virtual address srcva in a given page table,
// until a '\0', or max.
// Return 0 on success, -1 on error.
int
copyinstr(pagetable_t pagetable, char *dst, uint64 srcva, uint64 max)
{
  uint64 n, va0, pa0;
  int got_null = 0;

  while(got_null == 0 && max > 0){
    va0 = PGROUNDDOWN(srcva);
    pa0 = walkaddr(pagetable, va0);
    if(pa0 == 0)
      return -1;
    n = PGSIZE - (srcva - va0);
    if(n > max)
      n = max;

    char *p = (char *) (pa0 + (srcva - va0));
    while(n > 0){
      if(*p == '\0'){
        *dst = '\0';
        got_null = 1;
        break;
      } else {
        *dst = *p;
      }
      --n;
      --max;
      p++;
      dst++;
    }

    srcva = va0 + PGSIZE;
  }
  if(got_null){
    return 0;
  } else {
    return -1;
  }
}

int err_ret = -1;   // return value for error

// Check if virtual address is mapped
int
ismapped(pagetable_t pagetable, uint64 va)
{
  pte_t *entry;
  
  if(va >= MAXVA)
    return 0;
  
  entry = walk(pagetable, va, 0);
  if(entry == 0)
    return 0;
  
  if(*entry & PTE_V)
    return 1;
  
  return 0;
}

// Handle page fault with demand paging
uint64
vmfault(pagetable_t pagetable, uint64 va, int write, int from_trap)
{
  uint64 mem;
  struct proc *currproc = myproc();
  
  va = PGROUNDDOWN(va);
  
  // Validate address range
  if(va >= MAXVA) {
    if(from_trap) {
      char *access_str = write ? "write" : "read";
      printf("[pid %d] PAGEFAULT va=0x%lx access=%s cause=invalid\n", currproc->pid, va, access_str);
      printf("[pid %d] KILL invalid-access va=0x%lx access=%s\n", currproc->pid, va, access_str);
      setkilled(currproc);
    }
    return 0;
  }
  
  // Check if already mapped
  if(ismapped(pagetable, va)) {
    return 0;
  }
  
  // Look for page in swap
  int slot = -1;
  int res_idx = -1;
  for(int idx = 0; idx < MAX_RESIDENT_PAGES; idx++) {
    if(currproc->resident_pages[idx].valid && currproc->resident_pages[idx].va == va && 
       currproc->resident_pages[idx].in_swap) {
      slot = currproc->resident_pages[idx].swap_slot;
      res_idx = idx;
      break;
    }
  }
  
  // Classify fault type
  char *access_str = write ? "write" : "read";
  char *fault_cause = 0;
  int valid = 0;
  
  // Determine cause
  if(slot >= 0) {
    fault_cause = "swap";
    valid = 1;
  } else {
    // Calculate heap start
    uint64 heap_begin = (currproc->data_end > currproc->text_end) ? currproc->data_end : currproc->text_end;
    if(heap_begin == 0) heap_begin = PGSIZE;
    
    uint64 stack_page = PGROUNDDOWN(currproc->trapframe->sp);
    //stack_page - PGSIZE is guard
    
    // Classify region
    if((currproc->text_start != 0xFFFFFFFF && va >= currproc->text_start && va < currproc->text_end)
      || (currproc->data_start != 0xFFFFFFFF && va >= currproc->data_start && va < currproc->data_end)) {
      fault_cause = "exec";
      valid = 1;
    } else if(va >= stack_page && va < currproc->sz) {
      fault_cause = "stack";
      valid = 1;
    } else if(va >= heap_begin && va < currproc->sz && va < (stack_page - PGSIZE)) {
      fault_cause = "heap";
      valid = 1;
    } else {
      fault_cause = "invalid";
      valid = 0;
    }
  }
  
  // Log fault
  if(from_trap)
    printf("[pid %d] PAGEFAULT va=0x%lx access=%s cause=%s\n", currproc->pid, va, access_str, fault_cause);
  
  // Handle invalid access
  if(!valid) {
    if(from_trap) {
      printf("[pid %d] KILL invalid-access va=0x%lx access=%s\n", currproc->pid, va, access_str);
      setkilled(currproc);
    }
    return 0;
  }
  
  // Check text segment write
  if(write && currproc->text_start != 0xFFFFFFFF && va >= currproc->text_start && va < currproc->text_end) {
    if(from_trap) {
      printf("[pid %d] KILL invalid-access va=0x%lx access=write\n", currproc->pid, va);
      setkilled(currproc);
    }
    return 0;
  }
  
  // Check if resident set is full and evict if necessary
  if(slot < 0 && currproc->num_resident >= MAX_RESIDENT_PAGES) {
    printf("[pid %d] MEMFULL\n", currproc->pid);
    
    uint64 evict_va;
    uint evict_seq;
    char evict_dirty;
    
    if(find_fifo_victim(currproc, &evict_va, &evict_seq, &evict_dirty) < 0) {
      printf("[pid %d] KILL swap-exhausted\n", currproc->pid);
      setkilled(currproc);
      return 0;
    }
    
    printf("[pid %d] VICTIM va=0x%lx seq=%d algo=FIFO\n", currproc->pid, evict_va, evict_seq);
    
    if(evict_page(currproc, evict_va, evict_dirty) < 0) {
      printf("[pid %d] KILL swap-exhausted\n", currproc->pid);
      setkilled(currproc);
      return 0;
    }
  }
  
  // Allocate memory
  mem = (uint64) kalloc();
  
  // Try eviction if allocation failed
  if(mem == 0) {
    printf("[pid %d] MEMFULL\n", currproc->pid);
    
    uint64 evict_va;
    uint evict_seq;
    char evict_dirty;
    
    if(find_fifo_victim(currproc, &evict_va, &evict_seq, &evict_dirty) < 0) {
      printf("[pid %d] KILL swap-exhausted\n", currproc->pid);
      setkilled(currproc);
      return 0;
    }
    
    printf("[pid %d] VICTIM va=0x%lx seq=%d algo=FIFO\n", currproc->pid, evict_va, evict_seq);
    
    int txn_needed = !in_transaction();
    if(txn_needed)
      begin_op();
    
    if(evict_page(currproc, evict_va, evict_dirty) < 0) {
      if(txn_needed)
        end_op();
      printf("[pid %d] KILL swap-exhausted\n", currproc->pid);
      setkilled(currproc);
      return 0;
    }
    
    if(txn_needed)
      end_op();
    
    // Retry allocation
    mem = (uint64) kalloc();
    if(mem == 0) {
      printf("[pid %d] KILL swap-exhausted\n", currproc->pid);
      setkilled(currproc);
      return 0;
    }
  }
  
  memset((void *) mem, 0, PGSIZE);
  
  // Load from swap if needed
  if(slot >= 0) {
    int txn_needed = !in_transaction();
    if(txn_needed)
      begin_op();
    
    if(read_from_swap(currproc, va, slot, mem) < 0) {
      if(txn_needed)
        end_op();
      kfree((void*)mem);
      setkilled(currproc);
      return 0;
    }
    
    if(txn_needed)
      end_op();
    
    printf("[pid %d] SWAPIN va=0x%lx slot=%d\n", currproc->pid, va, slot);
    
    // Release swap slot
    free_swap_slot(currproc, slot);
    
    // Update resident entry
    if(res_idx >= 0) {
      currproc->resident_pages[res_idx].in_swap = 0;
      currproc->resident_pages[res_idx].swap_slot = -1;
      currproc->num_resident++;
    }
    
    // Set permissions
    int perms = PTE_U | PTE_R;
    if(!(va >= currproc->text_start && va < currproc->text_end))
      perms |= PTE_W;
    else
      perms |= PTE_X;
    
    // Map page
    if(mappages(pagetable, va, PGSIZE, mem, perms) != 0) {
      kfree((void*)mem);
      setkilled(currproc);
      return 0;
    }
    
    printf("[pid %d] RESIDENT va=0x%lx seq=%d\n", currproc->pid, va, currproc->next_seq);
    
    if(res_idx >= 0)
      currproc->resident_pages[res_idx].seq = currproc->next_seq++;
    
    return mem;
  }
  
  // Determine permissions
  int perms = PTE_U | PTE_R;
  if(va >= currproc->text_start && va < currproc->text_end)
    perms |= PTE_X;
  else
    perms |= PTE_W;
  
  // Load from executable if text/data segment
  if((va >= currproc->text_start && va < currproc->text_end) || 
     (va >= currproc->data_start && va < currproc->data_end)) {
    
    if(currproc->exec_inode == 0) {
      printf("[EXEC_INODE_NULL] pid=%d va=0x%lx\n", currproc->pid, va);
      kfree((void*)mem);
      setkilled(currproc);
      return 0;
    }
    
    // Load page from executable
    struct elfhdr hdr;
    struct proghdr phdr;
    
    ilock(currproc->exec_inode);
    
    // Read ELF header
    if(readi(currproc->exec_inode, 0, (uint64)&hdr, 0, sizeof(hdr)) != sizeof(hdr)) {
      iunlock(currproc->exec_inode);
      kfree((void*)mem);
      setkilled(currproc);
      return 0;
    }
    
    // Find segment
    int located = 0;
    for(int j = 0, offset = hdr.phoff; j < hdr.phnum; j++, offset += sizeof(phdr)){
      if(readi(currproc->exec_inode, 0, (uint64)&phdr, offset, sizeof(phdr)) != sizeof(phdr)) {
        iunlock(currproc->exec_inode);
        kfree((void*)mem);
        setkilled(currproc);
        return 0;
      }
      if(phdr.type != ELF_PROG_LOAD)
        continue;
      
      // Check if va in segment
      if(va >= phdr.vaddr && va < phdr.vaddr + phdr.memsz) {
        // Calculate offset
        uint64 seg_offset = va - phdr.vaddr;
        uint64 file_off = phdr.off + seg_offset;
        
        // Read from file
        if(seg_offset < phdr.filesz) {
          uint read_size = PGSIZE;
          if(seg_offset + PGSIZE > phdr.filesz)
            read_size = phdr.filesz - seg_offset;
          
          if(readi(currproc->exec_inode, 0, mem, file_off, read_size) != read_size) {
            iunlock(currproc->exec_inode);
            kfree((void*)mem);
            setkilled(currproc);
            return 0;
          }
        }
        located = 1;
        break;
      }
    }
    
    iunlock(currproc->exec_inode);
    
    if(!located) {
      kfree((void*)mem);
      setkilled(currproc);
      return 0;
    }
    
    printf("[pid %d] LOADEXEC va=0x%lx\n", currproc->pid, va);
  } else {
    // Heap or stack
    printf("[pid %d] ALLOC va=0x%lx\n", currproc->pid, va);
  }
  
  // Map page
  if (mappages(currproc->pagetable, va, PGSIZE, mem, perms) != 0) {
    kfree((void *)mem);
    setkilled(currproc);
    return 0;
  }
  
  // Add to resident set
  add_resident_page(currproc, va, currproc->next_seq, 0);
  
  printf("[pid %d] RESIDENT va=0x%lx seq=%d\n", currproc->pid, va, currproc->next_seq);
  currproc->next_seq++;
  
  return mem;
}

// Add page to resident set
void
add_resident_page(struct proc *currproc, uint64 va, uint seq, char dirty)
{
  // Check if page has executable backing
  char exec_backed = 0;
  
  if(va >= currproc->text_start && va < currproc->text_end)
    exec_backed = 1;
  else if(va >= currproc->data_start && va < currproc->data_end)
    exec_backed = 1;
  
  // Find free slot
  for(int idx = 0; idx < MAX_RESIDENT_PAGES; idx++) {
    if(!currproc->resident_pages[idx].valid || (currproc->resident_pages[idx].valid && currproc->resident_pages[idx].in_swap)) {
      currproc->resident_pages[idx].va = va;
      currproc->resident_pages[idx].seq = seq;
      currproc->resident_pages[idx].dirty = dirty;
      currproc->resident_pages[idx].valid = 1;
      currproc->resident_pages[idx].in_swap = 0;
      currproc->resident_pages[idx].swap_slot = -1;
      currproc->resident_pages[idx].has_exec_backing = exec_backed;
      currproc->num_resident++;
      return;
    }
  }
  panic("add_resident_page: no free slots");
}

// Remove page from resident set
void
remove_resident_page(struct proc *currproc, uint64 va)
{
  for(int idx = 0; idx < MAX_RESIDENT_PAGES; idx++) {
    if(currproc->resident_pages[idx].valid && currproc->resident_pages[idx].va == va) {
      if(currproc->resident_pages[idx].in_swap && currproc->resident_pages[idx].swap_slot >= 0)
        free_swap_slot(currproc, currproc->resident_pages[idx].swap_slot);
      
      currproc->resident_pages[idx].valid = 0;
      currproc->num_resident--;
      return;
    }
  }
}

// Mark page as modified
void
mark_page_dirty(struct proc *currproc, uint64 va)
{
  for(int idx = 0; idx < MAX_RESIDENT_PAGES; idx++) {
    if(currproc->resident_pages[idx].valid && currproc->resident_pages[idx].va == va) {
      currproc->resident_pages[idx].dirty = 1;
      return;
    }
  }
}

// Find victim using FIFO
int
find_fifo_victim(struct proc *currproc, uint64 *evict_va, uint *evict_seq, char *evict_dirty)
{
  if(currproc->num_resident == 0)
    return err_ret;
  
  int evict_idx = -1;
  uint min_seq = 0xFFFFFFFF;
  
  for(int idx = 0; idx < MAX_RESIDENT_PAGES; idx++) {
    if(currproc->resident_pages[idx].valid && !currproc->resident_pages[idx].in_swap) {
      if(evict_idx == -1 || currproc->resident_pages[idx].seq < min_seq) {
        min_seq = currproc->resident_pages[idx].seq;
        evict_idx = idx;
      }
    }
  }
  
  if(evict_idx >= 0) {
    *evict_va = currproc->resident_pages[evict_idx].va;
    *evict_seq = currproc->resident_pages[evict_idx].seq;
    *evict_dirty = currproc->resident_pages[evict_idx].dirty;
    return evict_idx;
  }
  
  return err_ret;
}

int
evict_page(struct proc *currproc, uint64 va, char dirty)
{
  pte_t *pte_entry;
  uint64 phys_addr;
  int slot = -1;

  int txn_active = 0;
  if(!in_transaction()){
    begin_op();
    txn_active = 1;
  }

  pte_entry = walk(currproc->pagetable, va, 0);
  if(pte_entry == 0 || (*pte_entry & PTE_V) == 0) {
    if(txn_active)
      end_op();
    return -1;
  }

  phys_addr = PTE2PA(*pte_entry);

  // Find resident entry
  int res_idx = -1;
  char exec_backed = 0;
  for(int idx = 0; idx < MAX_RESIDENT_PAGES; idx++) {
    if(currproc->resident_pages[idx].valid && currproc->resident_pages[idx].va == va) {
      res_idx = idx;
      exec_backed = currproc->resident_pages[idx].has_exec_backing;
      break;
    }
  }

  if(dirty || !exec_backed) {
    // Write dirty page to swap
    if(currproc->swapfile == 0) {
      if(create_swap_file(currproc) < 0) {
        printf("[pid %d] KILL swap-exhausted (no swapfile)\n", currproc->pid);
        setkilled(currproc);
        if(txn_active)
          end_op();
        return err_ret;
      }
    }

    slot = alloc_swap_slot(currproc);
    if(slot < 0) {
      printf("[pid %d] SWAPFULL num_swap_used=%d\n", currproc->pid, currproc->num_swap_used);
      printf("[pid %d] KILL swap-exhausted\n", currproc->pid);
      setkilled(currproc);
      if(txn_active)
        end_op();
      return err_ret;
    }

    if(write_to_swap(currproc, va, slot) < 0) {
      printf("[pid %d] SWAPWRITE_FAILED swapfile=%p\n", currproc->pid, currproc->swapfile);
      free_swap_slot(currproc, slot);
      if(txn_active)
        end_op();
      return err_ret;
    }

    printf("[pid %d] EVICT  va=0x%lx state=dirty\n", currproc->pid, va);
    printf("[pid %d] SWAPOUT va=0x%lx slot=%d\n", currproc->pid, va, slot);

    if(res_idx > -1) {
      currproc->resident_pages[res_idx].in_swap = 1;
      currproc->resident_pages[res_idx].swap_slot = slot;
    }
  } else {
    // Clean page - discard
    printf("[pid %d] EVICT  va=0x%lx state=clean\n", currproc->pid, va);
    printf("[pid %d] DISCARD va=0x%lx\n", currproc->pid, va);
  }

  // Unmap and free
  *pte_entry = 0;
  kfree((void*)phys_addr);

  // Update resident set
  if(slot < 0) {
    remove_resident_page(currproc, va);
  } else {
    if(res_idx >= 0) {
      currproc->resident_pages[res_idx].in_swap = 1;
      currproc->resident_pages[res_idx].swap_slot = slot;
      currproc->num_resident--;
    }
  }

  if(txn_active)
    end_op();
  
  return 0;
}

// Allocate swap slot
int
alloc_swap_slot(struct proc *currproc)
{
  for(int slot_idx = 0; slot_idx < MAX_SWAP_SLOTS; slot_idx++) {
    if(currproc->swap_slots[slot_idx] == 0) {
      currproc->swap_slots[slot_idx] = 1;
      currproc->num_swap_used++;
      return slot_idx;
    }
  }
  return err_ret;
}

// Create process swap file
int
create_swap_file(struct proc *currproc)
{
  char filename[16];
  filename[0] = '/';
  filename[1] = 'p';
  filename[2] = 'g';
  filename[3] = 's';
  filename[4] = 'w';
  filename[5] = 'p';
  
  int pid_val = currproc->pid;
  for(int pos = 10; pos >= 6; pos--) {
    filename[pos] = '0' + (pid_val % 10);
    pid_val /= 10;
  }
  filename[11] = '\0';
  
  struct inode *swap_inode = create(filename, T_FILE, 0, 0);
  if(swap_inode == 0) {
    printf("[pid %d] LAZY: Failed to create swap file %s\n", currproc->pid, filename);
    return err_ret;
  }
  
  iunlock(swap_inode);
  currproc->swapfile = filealloc();
  if(currproc->swapfile == 0) {
    printf("[pid %d] LAZY: Failed to allocate file struct\n", currproc->pid);
    ilock(swap_inode);
    iunlockput(swap_inode);
    return err_ret;
  }
  
  currproc->swapfile->type = FD_INODE;
  currproc->swapfile->ip = swap_inode;
  currproc->swapfile->off = 0;
  currproc->swapfile->readable = 1;
  currproc->swapfile->writable = 1;
  printf("[pid %d] LAZY: Created swap file %s\n", currproc->pid, filename);
  
  return 0;
}

// Release swap slot
void
free_swap_slot(struct proc *currproc, int slot)
{
  if(slot >= 0 && slot < MAX_SWAP_SLOTS && currproc->swap_slots[slot]) {
    currproc->swap_slots[slot] = 0;
    currproc->num_swap_used--;
  }
}

int 
byte_reader(struct proc *currproc, uint64 pa, uint64 file_offset) {
  ilock(currproc->swapfile->ip);
  int bytes_read = readi(currproc->swapfile->ip, 0, pa, file_offset, PGSIZE);
  iunlock(currproc->swapfile->ip);
  return bytes_read;
}

int 
byte_writer(struct proc *currproc, uint64 phys_addr, uint64 file_offset) {
  ilock(currproc->swapfile->ip);
  int bytes_written = writei(currproc->swapfile->ip, 0, phys_addr, file_offset, PGSIZE);
  iunlock(currproc->swapfile->ip);
  return bytes_written;
}

// Write page to swap
int
write_to_swap(struct proc *currproc, uint64 va, int slot)
{
  if(!currproc->swapfile->ip || !currproc->swapfile) {
    return err_ret;
  }
  
  pte_t *pte_entry = walk(currproc->pagetable, va, 0);
  if(pte_entry == 0 || (*pte_entry & PTE_V) == 0) {
    return err_ret;
  }
  uint64 phys_addr = PTE2PA(*pte_entry);
  uint64 file_offset = slot * PGSIZE;
  int bytes_written = byte_writer(currproc, phys_addr, file_offset);

  if(bytes_written != PGSIZE) {
    return err_ret;
  }
  return 0;
}

// Read page from swap  
int
read_from_swap(struct proc *currproc, uint64 va, int slot, uint64 pa)
{
  if(!currproc->swapfile || !currproc->swapfile->ip) {
    return err_ret;
  }
  uint64 file_offset = slot * PGSIZE;
  int bytes_read = byte_reader(currproc, pa, file_offset);
  if(bytes_read != PGSIZE) {
    return err_ret;
  }
  return 0;
}
