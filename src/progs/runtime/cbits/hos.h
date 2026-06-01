#ifndef __hos_H__
#define __hos_H__

#include <stdint.h>
#include <stddef.h>

#define LACKS_TIME_H 1
#define LACKS_STRIGS_H 1
#define LACKS_STRING_H 1
#define LACKS_FCNTL_H 1
#define LACKS_UNISTD_H 1
#define HAVE_MMAP 0
#define NO_MALLOC_STATS 1
#define MALLOC_FAILURE_ACTION abort()

#if TARGET == i386 || TARGET == x86_64
#define EXEC_PAGESIZE 0x1000
#endif

#if TARGET == x86_64
/* We have tons of space on a 64-bit architecture, so just start the heap at the 512th gigabyte */
#define HEAP_START 0x8000000000
#define HOS_IS_64_BIT 1
#elif TARGET == i386
#define HOS_IS_32_BIT
#endif



/* Some shims for string.h */
void *memcpy(void *dest, const void *src, size_t n);
void *memset(void *s, int c, size_t n);
void *malloc(size_t size);
void free(void *ptr);
void *realloc(void *ptr, size_t size);
int fprintf(void *stream, const char *format, ...);
void abort();
void hos_init_clear_bss();

/* JHC integration - implemented in hos.c */
/* Moved outside for forced definition */
void jhc_utf8_putchar(int ch);
void jhc_exit(int n);
void jhc_case_fell_off(int n);
void klog(const char *msg);
void klog_hex(unsigned long n);
void abort(void);
uint8_t inb(uint16_t port);
void outb(uint16_t port, uint8_t val);
uint8_t hosIn8(uint16_t port);
uint16_t hosIn16(uint16_t port);
uint32_t hosIn32(uint16_t port);
void hosOut8(uint16_t port, uint8_t val);
void hosOut16(uint16_t port, uint16_t val);
void hosOut32(uint16_t port, uint32_t val);

void *ext_page_aligned_alloc(size_t size);
void *ext_page_aligned_realloc(void *ptr, size_t sz);
void ext_free(void *ptr, size_t size);
void *ext_alloc_megablock(void);
void *ext_alloc_cache(void);
void hos_reset_malloc_after_fork(void);
uint64_t hos_fork_enter_address_space(uint64_t aRef, uint64_t entry);
uint64_t hos_fork_enter_linux_address_space(uint64_t aRef, uint64_t entry, void *start_info);
void hos_spawn_enter_address_space(uint64_t aRef, uint64_t entry);
void hos_spawn_enter_linux_address_space(uint64_t aRef, uint64_t entry, void *start_info);
void hos_yield_many(uint64_t count);
uint64_t hos_wait_on_channels_raw(uint64_t flags, uint64_t timeout);
uint32_t hos_wait_on_channels_task(void);

void *malloc(size_t size);
void free(void *ptr);
void *realloc(void *ptr, size_t size);
int fprintf(void *stream, const char *format, ...);


static inline void *word_to_ptr(uintptr_t i)
{
  return (void*) i;
}

static inline uintptr_t ptr_to_word(void *i)
{
  return (uintptr_t) i;
}

#if 0
static inline double frexp(double x, int *exp)
{
  return __builtin_frexp(x, exp);
};
static inline float frexpf(float x, int *exp)
{
  return __builtin_frexpf(x, exp);
};
static inline double ldexp(double x, int exp)
{
  return __builtin_ldexp(x, exp);
};
static inline double ceil(double x)
{
  return __builtin_ceil(x);
};
static inline double log(double x)
{
  return __builtin_log(x);
}
#endif

#endif

/* JHC integration - forced definition */
void c_assert(int condition);
#undef assert
#define assert(e) c_assert(!!(e))
