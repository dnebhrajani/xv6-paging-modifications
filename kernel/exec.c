#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "elf.h"
#include "sleeplock.h"
#include "fs.h"
#include "file.h"
#include "stat.h"

static int setupseg_lazy(pagetable_t, uint64, uint64, int);

// map ELF permissions to PTE permission bits.
int flags2perm(int flags)
{
    int perm = 0;
    if(flags & 0x1)
      perm = PTE_X;
    if(flags & 0x2)
      perm |= PTE_W;
    return perm;
}

int
kexec(char *path, char **argv)
{
  char *s, *last;
  int i, off;
  uint64 argc, sz = 0, sp, ustack[MAXARG], stackbase;
  struct elfhdr elf;
  struct inode *ip;
  struct proghdr ph;
  pagetable_t pagetable = 0, oldpagetable;
  struct proc *p = myproc();

  begin_op();

  if((ip = namei(path)) == 0){
    end_op();
    return -1;
  }
  ilock(ip);

  if(readi(ip, 0, (uint64)&elf, 0, sizeof(elf)) != sizeof(elf))
    goto bad;

  if(elf.magic != ELF_MAGIC)
    goto bad;

  if((pagetable = proc_pagetable(p)) == 0)
    goto bad;

  // lazy segments setup
  p->data_start = 0xFFFFFFFF;
  p->data_end = 0;
  p->text_start = 0xFFFFFFFF;
  p->text_end = 0;
  
  for(i = 0, off = elf.phoff; i < elf.phnum; i++, off += sizeof(ph)){
    if(readi(ip, 0, (uint64)&ph, off, sizeof(ph)) != sizeof(ph))
      goto bad;
    if(ph.type != ELF_PROG_LOAD)
      continue;
    if(ph.memsz < ph.filesz)
      goto bad;
    if(ph.vaddr + ph.memsz < ph.vaddr)
      goto bad;
    if(ph.vaddr % PGSIZE != 0)
      goto bad;
    
    // record segment boundaries
    int perm = flags2perm(ph.flags);
    if(!(perm & PTE_X)) {
      if(p->data_start == 0xFFFFFFFF || ph.vaddr < p->data_start)
        p->data_start = ph.vaddr;
      if(ph.vaddr + ph.memsz > p->data_end)
        p->data_end = ph.vaddr + ph.memsz;
    } 
    else {
      if(p->text_start == 0xFFFFFFFF || ph.vaddr < p->text_start)
        p->text_start = ph.vaddr;
      if(ph.vaddr + ph.memsz > p->text_end)
        p->text_end = ph.vaddr + ph.memsz;
    }
    
    // setup page table entries
    if(setupseg_lazy(pagetable, ph.vaddr, ph.vaddr + ph.memsz, perm) < 0)
      goto bad;
    
    if(ph.vaddr + ph.memsz > sz)
      sz = ph.vaddr + ph.memsz;
  }
  
  p->exec_inode = idup(ip);
  
  iunlock(ip);
  end_op();
  ip = 0;

  p = myproc();
  uint64 oldsz = p->sz;

  // setup stack
  sz = PGROUNDUP(sz);
  sz += (USERSTACK+1)*PGSIZE;
  
  sp = sz;
  stackbase = sp - USERSTACK*PGSIZE;

  // allocate top stack page for args
  uint64 stackpage = sp - PGSIZE;
  char *mem = kalloc();
  if(mem == 0)
    goto bad;
  memset(mem, 0, PGSIZE);
  if(mappages(pagetable, stackpage, PGSIZE, (uint64)mem, PTE_R|PTE_W|PTE_U) != 0) {
    kfree(mem);
    goto bad;
  }
  
  p->next_seq = 1;

  // copy args to stack
  for(argc = 0; argv[argc]; argc++) {
    if(argc >= MAXARG)
      goto bad;
    sp -= strlen(argv[argc]) + 1;
    sp -= sp % 16;
    if(sp < stackbase)
      goto bad;
    if(copyout(pagetable, sp, argv[argc], strlen(argv[argc]) + 1) < 0)
      goto bad;
    ustack[argc] = sp;
  }
  ustack[argc] = 0;

  sp -= (argc+1) * sizeof(uint64);
  sp -= sp % 16;
  if(sp < stackbase)
    goto bad;
  if(copyout(pagetable, sp, (char *)ustack, (argc+1)*sizeof(uint64)) < 0)
    goto bad;

  p->trapframe->a1 = sp;

  for(last = s = path; *s; s++)
    if(*s == '/')
      last = s+1;
  safestrcpy(p->name, last, sizeof(p->name));
    
  oldpagetable = p->pagetable;
  p->pagetable = pagetable;
  p->sz = sz;
  p->trapframe->epc = elf.entry;
  p->trapframe->sp = sp;
  proc_freepagetable(oldpagetable, oldsz);

  // create swap file
  char swapname[16];
  swapname[0] = '/';
  swapname[1] = 'p';
  swapname[2] = 'g';
  swapname[3] = 's';
  swapname[4] = 'w';
  swapname[5] = 'p';
  
  int pid = p->pid;
  for(i = 10; i >= 6; i--) {
    swapname[i] = '0' + (pid % 10);
    pid /= 10;
  }
  swapname[11] = '\0';
  
  if(p->swapfile) {
    fileclose(p->swapfile);
    p->swapfile = 0;
  }
  
  begin_op();
  struct inode *swapip = create(swapname, T_FILE, 0, 0);
  if(swapip != 0) {
    iunlock(swapip);
    p->swapfile = filealloc();
    if(p->swapfile != 0) {
      p->swapfile->type = FD_INODE;
      p->swapfile->ip = swapip;
      p->swapfile->readable = 1;
      p->swapfile->off = 0;
      p->swapfile->writable = 1;
      printf("[pid %d] EXEC: Created swap file %s\n", p->pid, swapname);
      end_op();
    } else {
      printf("[pid %d] EXEC: Failed to allocate file struct for swap\n", p->pid);
      ilock(swapip);
      iunlockput(swapip);
      end_op();
    }
  } else {
    printf("[pid %d] EXEC: Failed to create swap file %s\n", p->pid, swapname);
    end_op();
  }
  
  p->num_swap_used = 0;
  for(i = 0; i < MAX_SWAP_SLOTS; i++)
    p->swap_slots[i] = 0;
  
  printf("[pid %d] INIT-LAZYMAP text=[0x%lx,0x%lx) data=[0x%lx,0x%lx) heap_start=0x%lx stack_top=0x%lx\n",
         p->pid, (uint64)p->text_start, (uint64)p->text_end, (uint64)p->data_start, (uint64)p->data_end, (uint64)p->data_end, sz);

  return argc;

 bad:
  if(pagetable)
    proc_freepagetable(pagetable, sz);
  if(ip){
    iunlockput(ip);
    end_op();
  }
  return -1;
}

static int
setupseg_lazy(pagetable_t pagetable, uint64 va_start, uint64 va_end, int perm)
{
  pte_t *pte;
  
  va_start = PGROUNDDOWN(va_start);
  va_end = PGROUNDUP(va_end);
  
  for(uint64 a = va_start; a < va_end; a += PGSIZE) {
    pte = walk(pagetable, a, 1);
    if(pte == 0)
      return -1;
    *pte = 0;
  }
  
  return 0;
}


/*
// Load an ELF program segment into pagetable at virtual address va.
// va must be page-aligned
// and the pages from va to va+sz must already be mapped.
// Returns 0 on success, -1 on failure.
static int
loadseg(pagetable_t pagetable, uint64 va, struct inode *ip, uint offset, uint sz)
{
  uint i, n;
  uint64 pa;

  for(i = 0; i < sz; i += PGSIZE){
    pa = walkaddr(pagetable, va + i);
    if(pa == 0)
      panic("loadseg: address should exist");
    if(sz - i < PGSIZE)
      n = sz - i;
    else
      n = PGSIZE;
    if(readi(ip, 0, (uint64)pa, offset+i, n) != n)
      return -1;
  }

  return 0;
}*/