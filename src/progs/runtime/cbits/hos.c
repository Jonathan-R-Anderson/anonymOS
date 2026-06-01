#include "hos.h"
#include "syscall.h"

#include "stdio.h"

void *memcpy(void *dest, const void *src, size_t n)
{
    char *dp = dest;
    const char *sp = src;
    while (n--)
        *dp++ = *sp++;
    return dest;
}

void *memset(void *s, int c, unsigned long n)
{
  unsigned char* p=s;
  while(n--)
    *p++ = (unsigned char)c;
  return s;
}

void abort()
{
  asm("syscall" : : "A"(0x400));
}

void c_assert(int condition)
{
  if (!condition) {
    klog("ASSERTION FAILED in user program\n");
    jhc_exit(1);
  }
}

#undef assert
void assert(int condition)
{
  c_assert(condition);
}

void klog(const char *msg) {
    hos_debug_log(msg);
}

void klog_hex(unsigned long n) {
    // Simple hex printer for user-space log
    char buf[20];
    int i = 0;
    if (n == 0) {
        klog("0");
        return;
    }
    while (n > 0) {
        int rem = n % 16;
        if (rem < 10) buf[i++] = rem + '0';
        else buf[i++] = rem - 10 + 'a';
        n /= 16;
    }
    buf[i] = 0;
    // reverse buf
    for (int j = 0; j < i / 2; j++) {
        char tmp = buf[j];
        buf[j] = buf[i - j - 1];
        buf[i - j - 1] = tmp;
    }
    klog(buf);
}

void jhc_utf8_putchar(int ch) {}
void jhc_exit(int n) { abort(); }
void jhc_case_fell_off(int n) { abort(); }

/* External allocator stubs for RTS in barebones mode */
extern void *malloc(size_t size);
extern void free(void *ptr);
extern void *realloc(void *ptr, size_t size);
extern void *memalign(size_t alignment, size_t size);

void *ext_page_aligned_alloc(size_t size) {
    return memalign(4096, size);
}

void *ext_page_aligned_realloc(void *ptr, size_t size) {
    // memalign-style realloc is tricky, but realloc might work if aligned
    return realloc(ptr, size);
}

void ext_free(void *ptr, size_t size) {
    free(ptr);
}

void *ext_alloc_megablock() {
    return malloc(4096); // matches kernel stub
}

void *ext_alloc_cache() {
    return malloc(4096); // matches kernel stub
}

static void *heap_end_ptr = (void *) HEAP_START;
static uint32_t hos_last_wait_task = 0;

static inline uint64_t hos_syscall0_inline(uint64_t num)
{
#if TARGET == x86_64
  uint64_t ret;
  asm volatile ("syscall"
                : "=a"(ret)
                : "a"(num), "D"(0ULL), "S"(0ULL), "d"(0ULL)
                : "rcx", "r11", "memory");
  return ret;
#else
  return syscall(num, 0, 0, 0, 0, 0);
#endif
}

static inline uint64_t hos_syscall2_inline(uint64_t num, uint64_t arg1, uint64_t arg2)
{
#if TARGET == x86_64
  uint64_t ret;
  asm volatile ("syscall"
                : "=a"(ret)
                : "a"(num), "D"(arg1), "S"(arg2), "d"(0ULL)
                : "rcx", "r11", "memory");
  return ret;
#else
  return syscall(num, arg1, arg2, 0, 0, 0);
#endif
}

static inline uint64_t hos_syscall3_inline(uint64_t num, uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
#if TARGET == x86_64
  uint64_t ret;
  asm volatile ("syscall"
                : "=a"(ret)
                : "a"(num), "D"(arg1), "S"(arg2), "d"(arg3)
                : "rcx", "r11", "memory");
  return ret;
#else
  return syscall(num, arg1, arg2, arg3, 0, 0);
#endif
}

void* sbrk(ptrdiff_t space_to_add)
{
  ptrdiff_t aligned_space_to_add = (space_to_add + EXEC_PAGESIZE - 1) & ~(EXEC_PAGESIZE - 1);

  if ( aligned_space_to_add > 0 ) {
    uint64_t curAddrSpaceRef = 0xffffffff;
    mem_mapping_t mapping = {0, 0, 0};
    mapping.mapping_type = MAP_ALLOCATE_ON_DEMAND;
    mapping.perms = PERMS_USERSPACE_RW;
    hos_add_mapping((uint64_t) curAddrSpaceRef, (uintptr_t)heap_end_ptr, (uintptr_t)heap_end_ptr + (uintptr_t)aligned_space_to_add, (mem_mapping_t *) &mapping);
    heap_end_ptr += aligned_space_to_add;
  }
  return (void *) (((uintptr_t) heap_end_ptr) - aligned_space_to_add);
}

// Defined in dlmalloc.c - the global malloc state
extern char gm_; // mstate gm

// Defined in dlmalloc.c - the global malloc state
extern char _gm_; // mstate _gm_

// Reset malloc state after fork (for child process)
void hos_reset_malloc_after_fork(void)
{
  klog("Resetting malloc after fork\n");
  // Reset heap pointer
  heap_end_ptr = (void *) HEAP_START;
  // Clear dlmalloc's global state to force reinitialization
  // The _gm_ symbol is the global malloc_state structure
  memset(&_gm_, 0, 4096); // Clear the malloc state (it's less than 4K)
  klog("Malloc reset complete\n");
}

static void hos_enter_child_address_space(uint64_t aRef, uint64_t entry)
{
  /* This path immediately replaces the current address space. Resetting the
     dlmalloc globals before the switch can corrupt the parent if those data
     pages are still shared across the fork boundary. */
  klog("[userrt] enter_child_hos aref=");
  klog_hex(aRef);
  klog(" entry=");
  klog_hex(entry);
  klog("\n");
  hos_syscall2_inline(0x007, aRef, entry);
  abort();
}

static void hos_enter_child_linux_address_space(uint64_t aRef, uint64_t entry, void *start_info)
{
  /* Same rationale as hos_enter_child_address_space: do not mutate the
     current process heap state before the new address space takes over. */
  klog("[userrt] enter_child_linux aref=");
  klog_hex(aRef);
  klog(" entry=");
  klog_hex(entry);
  klog(" info=");
  klog_hex(ptr_to_word(start_info));
  klog("\n");
  hos_syscall3_inline(0x009, aRef, entry, (hos_word_t) start_info);
  abort();
}

uint64_t hos_fork_enter_address_space(uint64_t aRef, uint64_t entry)
{
  uint64_t raw = hos_syscall0_inline(0x402);
  uint64_t self = hos_syscall0_inline(HOS_CURRENT_TASK);
  klog("[userrt] fork_enter_hos raw=");
  klog_hex(raw);
  klog(" self=");
  klog_hex(self);
  klog(" aref=");
  klog_hex(aRef);
  klog(" entry=");
  klog_hex(entry);
  klog("\n");
  if (raw == 0) {
    klog("[userrt] fork_enter_hos child via raw==0\n");
    hos_enter_child_address_space(aRef, entry);
  }
  if (raw == self) {
    klog("[userrt] fork_enter_hos child via raw==self\n");
    hos_enter_child_address_space(aRef, entry);
  }
  klog("[userrt] fork_enter_hos parent returning ");
  klog_hex(raw);
  klog("\n");
  return raw;
}

void hos_spawn_enter_address_space(uint64_t aRef, uint64_t entry)
{
  uint64_t raw = syscall(0x402, 0, 0, 0, 0, 0);
  if (raw == 0) {
    hos_enter_child_address_space(aRef, entry);
  }
  if (raw == syscall(HOS_CURRENT_TASK, 0, 0, 0, 0, 0)) {
    hos_enter_child_address_space(aRef, entry);
  }
}

uint64_t hos_fork_enter_linux_address_space(uint64_t aRef, uint64_t entry, void *start_info)
{
  uint64_t raw = hos_syscall0_inline(0x402);
  uint64_t self = hos_syscall0_inline(HOS_CURRENT_TASK);
  klog("[userrt] fork_enter_linux raw=");
  klog_hex(raw);
  klog(" self=");
  klog_hex(self);
  klog(" aref=");
  klog_hex(aRef);
  klog(" entry=");
  klog_hex(entry);
  klog(" info=");
  klog_hex(ptr_to_word(start_info));
  klog("\n");
  if (raw == 0) {
    klog("[userrt] fork_enter_linux child via raw==0\n");
    hos_enter_child_linux_address_space(aRef, entry, start_info);
  }
  if (raw == self) {
    klog("[userrt] fork_enter_linux child via raw==self\n");
    hos_enter_child_linux_address_space(aRef, entry, start_info);
  }
  klog("[userrt] fork_enter_linux parent returning ");
  klog_hex(raw);
  klog("\n");
  return raw;
}

void hos_spawn_enter_linux_address_space(uint64_t aRef, uint64_t entry, void *start_info)
{
  uint64_t raw = syscall(0x402, 0, 0, 0, 0, 0);
  if (raw == 0) {
    hos_enter_child_linux_address_space(aRef, entry, start_info);
  }
  if (raw == syscall(HOS_CURRENT_TASK, 0, 0, 0, 0, 0)) {
    hos_enter_child_linux_address_space(aRef, entry, start_info);
  }
}

void hos_yield_many(uint64_t count)
{
  while (count-- > 0) {
    syscall(0x403, 0, 0, 0, 0, 0);
  }
}

uint64_t hos_wait_on_channels_raw(uint64_t flags, uint64_t timeout)
{
  hos_last_wait_task = 0;
  return syscall(0x103, flags, timeout, ptr_to_word(&hos_last_wait_task), 0, 0);
}

uint32_t hos_wait_on_channels_task(void)
{
  return hos_last_wait_task;
}

int fprintf(void *f, const char *fmt, ...)
{
  return 0;
}

size_t fwrite(const void * ptr, size_t size, size_t nitems, void * stream)
{
  return 0;
}


extern int _bss_start, _bss_end;
void hos_init_clear_bss()
{
  memset(&_bss_start, 0, ((uintptr_t) &_bss_end) - ((uintptr_t) &_bss_start));
}

uint8_t inb(uint16_t port)
{
    uint8_t ret;
    asm volatile ( "inb %1, %0" : "=a"(ret) : "Nd"(port) );
    return ret;
}

void outb(uint16_t port, uint8_t val)
{
    asm volatile ( "outb %0, %1" : : "a"(val), "Nd"(port) );
}

uint8_t hosIn8(uint16_t port) { return inb(port); }
uint16_t hosIn16(uint16_t port)
{
    uint16_t ret;
    asm volatile ( "inw %1, %0" : "=a"(ret) : "Nd"(port) );
    return ret;
}
uint32_t hosIn32(uint16_t port)
{
    uint32_t ret;
    asm volatile ( "inl %1, %0" : "=a"(ret) : "Nd"(port) );
    return ret;
}

void hosOut8(uint16_t port, uint8_t val) { outb(port, val); }
void hosOut16(uint16_t port, uint16_t val)
{
    asm volatile ( "outw %0, %1" : : "a"(val), "Nd"(port) );
}
void hosOut32(uint16_t port, uint32_t val)
{
    asm volatile ( "outl %0, %1" : : "a"(val), "Nd"(port) );
}
