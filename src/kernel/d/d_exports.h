// d_exports.h — public C interface to the EpinAnonymOS D kernel.
// Include this from any C translation unit that needs to call into the kernel.
#ifndef D_EXPORTS_H
#define D_EXPORTS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#ifndef _SIZE_T_DEFINED_
#define _SIZE_T_DEFINED_
typedef uint64_t size_t;
#endif

// ── Logging ────────────────────────────────────────────────────────────────
void klog(const char *msg);
void klog_hex(unsigned long n);
void write_serial(int c);
void vga_putchar(char c);
void vga_puts(const char *str);
void term_write(const char *str);
void term_putchar(char c);

// ── Assertions / panic ─────────────────────────────────────────────────────
void c_assert(int condition);
#define assert(x) c_assert(!!(x))
void abort(void);

// ── Kernel main entry (called from bootstrap_kernel) ──────────────────────
void d_kernel_main(void);

// ── Display / driver bridge ───────────────────────────────────────────────
int  d_init_display(void);
int  d_init_drivers(void);
int  d_display_is_ready(void);
int  d_drivers_are_ready(void);
void d_display_heartbeat(void);

// ── Task / TLS management ─────────────────────────────────────────────────
void     d_set_current_task_id(uint64_t taskId);
void     d_store_task_fsbase(uint64_t taskId, uint64_t base);
void     d_apply_task_fsbase(uint64_t taskId);
void     d_store_task_cleartid_phys(uint64_t taskId, uint64_t physAddr);
void     d_do_cleartid(uint64_t taskId);
void     update_current_fs_base(uint64_t base);
void     x64_clear_user_syscall_state(void);

// ── Physical memory ────────────────────────────────────────────────────────
uint64_t alloc_phys_page(void);
uint64_t alloc_phys_pages(uint64_t n);
void*    alloc_from_regions(uint64_t size);
void*    malloc(size_t size);
void     free(void* ptr);
void*    memset(void* s, int c, size_t n);
void     copy_phys_page(uint64_t srcPhys, uint64_t dstPhys);
void     free_from_regions(uint64_t ptr, uint64_t size);

// ── Virtual memory ─────────────────────────────────────────────────────────
void     map_page_for_kernel(uint64_t virt_addr, uint64_t phys_addr, uint64_t flags);
void     arch_invalidate_page(uint64_t pageAddr);
void     arch_unmap_init_task(void);
void     x64WriteCR3(uint64_t value);
uint64_t x64ReadCR3(void);
uint64_t x64ReadCR2(void);

// ── Page-table helpers (used by display / userland code) ──────────────────
void     x64_poke_pte(uint64_t* mapping, int i, uint64_t val);
uint64_t x64_peek_pte(uint64_t* mapping, int i);
void     x64_poke_u64(void* ptr, uint64_t val);
uint64_t x64_get_hhdm_offset(void);

// ── Userspace state ────────────────────────────────────────────────────────
extern uint8_t  curUserSpaceState[0x298];
extern uint8_t  kernelState[0x290];
extern uint64_t x64TrapErrorCode;
extern uint64_t x64LastSyscallRax;
extern uint64_t x64LastSyscallRdi;
extern uint64_t x64LastSyscallRsi;
extern uint64_t x64LastSyscallRdx;
extern uint64_t x64LastSyscallR10;
extern uint64_t x64LastSyscallR8;
extern uint64_t x64LastSyscallR9;
extern uint64_t x64LastSyscallRip;

uint64_t x64SwitchToUserspace(void* userState, void* kernelState_);
uint64_t x64_get_user_state_word(uint64_t index);
void     x64_set_user_state_word(uint64_t index, uint64_t value);
uint64_t x64_get_kernel_state_word(uint64_t index);
uint64_t x64_get_last_syscall_word(uint64_t index);
void     x64_pf_log(uint64_t vaddr);

// ── Interrupt / IDT setup ─────────────────────────────────────────────────
void setupSysCalls(void);
void x64_ready_for_userspace(void);
void x64_setup_full_idt(void);
void loadIdt(void* idtPtr);

// Interrupt vectors (trap0-31, irq0-15) defined in context.S
void trap0(void);  void trap1(void);  void trap2(void);  void trap3(void);
void trap4(void);  void trap5(void);  void trap6(void);  void trap7(void);
void trap8(void);  void trap9(void);  void trap10(void); void trap11(void);
void trap12(void); void trap13(void); void trap14(void); void trap15(void);
void trap16(void); void trap17(void); void trap18(void); void trap19(void);
void trap20(void); void trap21(void); void trap22(void); void trap23(void);
void trap24(void); void trap25(void); void trap26(void); void trap27(void);
void trap28(void); void trap29(void); void trap30(void); void trap31(void);
void irq0(void);   void irq1(void);   void irq2(void);   void irq3(void);
void irq4(void);   void irq5(void);   void irq6(void);   void irq7(void);
void irq8(void);   void irq9(void);   void irq10(void);  void irq11(void);
void irq12(void);  void irq13(void);  void irq14(void);  void irq15(void);

// ── TSS / GDT helpers ─────────────────────────────────────────────────────
extern uint8_t  kernelTmpStack_top;
extern uint8_t  tssArea[104];

// ── Boot module table ─────────────────────────────────────────────────────
extern int   g_module_count;
extern void* g_mboot_modules;
extern uint64_t init_module_phys_base;
uint64_t get_init_module_phys_base(void);

// ── Globals ────────────────────────────────────────────────────────────────
extern uint64_t hhdm_offset;
extern uint64_t g_current_task_id;

// ── Pointer utilities ─────────────────────────────────────────────────────
uint64_t ptrToWord(void* ptr);
void*    wordToPtr(uint64_t w);
uint64_t c_peek_u64(uint64_t addr);
uint16_t c_peek_u16(uint64_t addr);
uint32_t c_peek_u32(uint64_t addr);

// ── Stack seeding ─────────────────────────────────────────────────────────
uint64_t linux_seed_initial_stack(
    uint64_t stackPhys, uint64_t stackSize, uint64_t stackVirtBase,
    const uint64_t* infoWords, uint64_t pg);
uint64_t linux_seed_initial_stack_with_args(
    uint64_t stackPhys, uint64_t stackSize, uint64_t stackVirtBase,
    const uint64_t* infoWords, uint64_t pg,
    uint64_t argvUserVirt, uint64_t envpUserVirt);

// ── Linux syscall bridge (all implemented in core/syscalls/posix.d) ───────
typedef struct { uint64_t physBase; uint64_t fileSize; } FdPhysInfo;
bool c_get_fd_phys_info(int fd, FdPhysInfo* out_);
long linux_sys_lseek_wrap(uint64_t fd, uint64_t offset, uint64_t whence);

long linux_sys_read(unsigned long fd, unsigned long buf, unsigned long count);
long linux_sys_write(unsigned long fd, unsigned long buf, unsigned long count);
long linux_sys_open(unsigned long path, unsigned long flags, unsigned long mode);
long linux_sys_close(unsigned long fd);
long linux_sys_stat(unsigned long path, unsigned long statbuf);
long linux_sys_fstat(unsigned long fd, unsigned long stat_buf);
long linux_sys_lstat(unsigned long path, unsigned long statbuf);
long linux_sys_poll(unsigned long fds, unsigned long nfds, unsigned long timeout);
long linux_sys_lseek(unsigned long fd, long offset, unsigned long whence);
long linux_sys_mmap(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd2, unsigned long offset);
long linux_sys_mprotect(unsigned long addr, unsigned long len, unsigned long prot);
long linux_sys_munmap(unsigned long addr, unsigned long len);
long linux_sys_brk(unsigned long addr);
long linux_sys_ioctl(unsigned long fd, unsigned long cmd, unsigned long arg);
long linux_sys_pread64(unsigned long fd, unsigned long buf, unsigned long count, unsigned long offset);
long linux_sys_pwrite64(unsigned long fd, unsigned long buf, unsigned long count, unsigned long offset);
long linux_sys_readv(unsigned long fd, unsigned long iov, unsigned long iovcnt);
long linux_sys_writev(unsigned long fd, unsigned long iov, unsigned long iovcnt);
long linux_sys_access(unsigned long path, unsigned long mode);
long linux_sys_pipe(unsigned long pipefd);
long linux_sys_select(unsigned long n, unsigned long inp, unsigned long outp, unsigned long exp, unsigned long tvp);
long linux_sys_sched_yield(void);
long linux_sys_madvise(unsigned long addr, unsigned long len, unsigned long advice);
long linux_sys_dup(unsigned long fildes);
long linux_sys_dup2(unsigned long oldfd, unsigned long newfd);
long linux_sys_pause(void);
long linux_sys_nanosleep(unsigned long rqtp, unsigned long rmtp);
long linux_sys_getitimer(unsigned long which, unsigned long value);
long linux_sys_alarm(unsigned long seconds);
long linux_sys_getpid(void);
long linux_sys_socket(unsigned long family, unsigned long type, unsigned long protocol);
long linux_sys_connect(unsigned long fd, unsigned long uservaddr, unsigned long addrlen);
long linux_sys_accept(unsigned long fd, unsigned long upeer_sockaddr, unsigned long upeer_addrlen);
long linux_sys_sendto(unsigned long fd, unsigned long buff, unsigned long len, unsigned long flags, unsigned long addr, unsigned long addr_len);
long linux_sys_recvfrom(unsigned long fd, unsigned long ubuf, unsigned long size, unsigned long flags, unsigned long addr, unsigned long addr_len);
long linux_sys_sendmsg(unsigned long fd, unsigned long msg, unsigned long flags);
long linux_sys_recvmsg(unsigned long fd, unsigned long msg, unsigned long flags);
long linux_sys_shutdown(unsigned long fd, unsigned long how);
long linux_sys_bind(unsigned long fd, unsigned long umyaddr, unsigned long addrlen);
long linux_sys_listen(unsigned long fd, unsigned long backlog);
long linux_sys_getsockname(unsigned long fd, unsigned long usockaddr, unsigned long uaddrlen);
long linux_sys_getpeername(unsigned long fd, unsigned long usockaddr, unsigned long uaddrlen);
long linux_sys_socketpair(unsigned long family, unsigned long type, unsigned long protocol, unsigned long usockvec);
long linux_sys_setsockopt(unsigned long fd, unsigned long level, unsigned long optname, unsigned long optval, unsigned long optlen);
long linux_sys_getsockopt(unsigned long fd, unsigned long level, unsigned long optname, unsigned long optval, unsigned long optlen);
long linux_sys_clone(unsigned long flags, unsigned long child_stack, unsigned long parent_tidptr, unsigned long child_tidptr, unsigned long tls);
long linux_sys_fork(void);
long linux_sys_execve(unsigned long filename, unsigned long argv, unsigned long envp);
long linux_sys_exit(unsigned long error_code);
long linux_sys_exit_group(unsigned long error_code);
long linux_sys_wait4(unsigned long upid, unsigned long stat_addr, unsigned long options, unsigned long rusage);
long linux_sys_kill(unsigned long pid, unsigned long sig);
long linux_sys_uname(unsigned long buf);
long linux_sys_fcntl(unsigned long fd, unsigned long cmd, unsigned long arg);
long linux_sys_getcwd(unsigned long buf, unsigned long size);
long linux_sys_chdir(unsigned long filename);
long linux_sys_readlink(unsigned long path, unsigned long buf, unsigned long bufsiz);
long linux_sys_getuid(void);
long linux_sys_getgid(void);
long linux_sys_setuid(unsigned long uid);
long linux_sys_setgid(unsigned long gid);
long linux_sys_geteuid(void);
long linux_sys_getegid(void);
long linux_sys_setpgid(unsigned long pid, unsigned long pgid);
long linux_sys_getppid(void);
long linux_sys_getpgrp(void);
long linux_sys_setsid(void);
long linux_sys_setresuid(unsigned long ruid, unsigned long euid, unsigned long suid);
long linux_sys_getresuid(unsigned long ruid, unsigned long euid, unsigned long suid);
long linux_sys_setresgid(unsigned long rgid, unsigned long egid, unsigned long sgid);
long linux_sys_getresgid(unsigned long rgid, unsigned long egid, unsigned long sgid);
long linux_sys_getpgid(unsigned long pid);
long linux_sys_gettid(void);
long linux_sys_gettimeofday(unsigned long tv, unsigned long tz);
long linux_sys_getrlimit(unsigned long resource, unsigned long rlim);
long linux_sys_setrlimit(unsigned long resource, unsigned long rlim);
long linux_sys_sysinfo(unsigned long info);
long linux_sys_times(unsigned long tbuf);
long linux_sys_prctl(unsigned long option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
long linux_sys_arch_prctl(unsigned long code, unsigned long addr);
long linux_sys_rt_sigaction(unsigned long signum, unsigned long act, unsigned long oldact, unsigned long sigsetsize);
long linux_sys_rt_sigprocmask(unsigned long how, unsigned long nset, unsigned long oldset, unsigned long sigsetsize);
long linux_sys_rt_sigreturn(void);
long linux_sys_sigaltstack(unsigned long ss, unsigned long oss);
long linux_sys_futex(unsigned long uaddr, unsigned long op, unsigned long val, unsigned long timeout, unsigned long uaddr2, unsigned long val3);
long linux_sys_set_tid_address(unsigned long tidptr);
long linux_sys_set_robust_list(unsigned long head, unsigned long len);
long linux_sys_clock_gettime(unsigned long clk_id, unsigned long tp);
long linux_sys_clock_getres(unsigned long clk_id, unsigned long tp);
long linux_sys_clock_nanosleep(unsigned long clk_id, unsigned long flags, unsigned long rqtp, unsigned long rmtp);
long linux_sys_getrandom(unsigned long buf, unsigned long buflen, unsigned long flags);
long linux_sys_prlimit64(unsigned long pid, unsigned long resource, unsigned long new_limit, unsigned long old_limit);
long linux_sys_rseq(unsigned long rseq, unsigned long rseq_len, unsigned long flags, unsigned long sig);
long linux_sys_pipe2(unsigned long fildes, unsigned long flags);
long linux_sys_dup3(unsigned long oldfd, unsigned long newfd, unsigned long flags);
long linux_sys_accept4(unsigned long fd, unsigned long upeer_sockaddr, unsigned long upeer_addrlen, unsigned long flags);
long linux_sys_epoll_create1(unsigned long flags);
long linux_sys_epoll_ctl(unsigned long epfd, unsigned long op, unsigned long fd, unsigned long event);
long linux_sys_epoll_pwait(unsigned long epfd, unsigned long events, unsigned long maxevents, unsigned long timeout, unsigned long sigmask, unsigned long sigsetsize);
long linux_sys_signalfd4(unsigned long ufd, unsigned long user_mask, unsigned long sizemask, unsigned long flags);
long linux_sys_timerfd_create(unsigned long clockid, unsigned long flags);
long linux_sys_eventfd2(unsigned long count, unsigned long flags);
long linux_sys_inotify_init1(unsigned long flags);
long linux_sys_openat(unsigned long dirfd, unsigned long path, unsigned long flags, unsigned long mode);
long linux_sys_mkdirat(unsigned long dfd, unsigned long pathname, unsigned long mode);
long linux_sys_newfstatat(unsigned long dirfd, unsigned long path, unsigned long statbuf, unsigned long flags);
long linux_sys_unlinkat(unsigned long dfd, unsigned long pathname, unsigned long flag);
long linux_sys_renameat2(unsigned long olddfd, unsigned long oldname, unsigned long newdfd, unsigned long newname, unsigned long flags);
long linux_sys_fchmodat(unsigned long dfd, unsigned long filename, unsigned long mode, unsigned long flags);
long linux_sys_fchownat(unsigned long dfd, unsigned long filename, unsigned long user, unsigned long group, unsigned long flags);
long linux_sys_symlinkat(unsigned long oldname, unsigned long newdfd, unsigned long newname);
long linux_sys_readlinkat(unsigned long dfd, unsigned long pathname, unsigned long buf, unsigned long bufsiz);
long linux_sys_statx(unsigned long dfd, unsigned long filename, unsigned long flags, unsigned long mask, unsigned long buffer);
long linux_sys_memfd_create(unsigned long name, unsigned long flags);
long linux_sys_statfs(unsigned long path, unsigned long buf);
long linux_sys_splice(unsigned long fd_in, unsigned long off_in, unsigned long fd_out, unsigned long off_out, unsigned long len, unsigned long flags);
long linux_sys_tee(unsigned long fd_in, unsigned long fd_out, unsigned long len, unsigned long flags);
long linux_sys_recvmmsg(unsigned long fd, unsigned long mmsg, unsigned long vlen, unsigned long flags, unsigned long timeout);
long linux_sys_ppoll(unsigned long ufds, unsigned long nfds, unsigned long tsp, unsigned long sigmask, unsigned long sigsetsize);
long linux_sys_pselect6(unsigned long n, unsigned long inp, unsigned long outp, unsigned long exp, unsigned long tsp, unsigned long sig);
long linux_sys_clone3(unsigned long ucltx, unsigned long size);
long linux_sys_execveat(unsigned long dfd, unsigned long filename, unsigned long argv, unsigned long envp, unsigned long flags);
long linux_sys_sync(void);
long linux_sys_mount(unsigned long dev_name, unsigned long dir_name, unsigned long type, unsigned long flags, unsigned long data);
long linux_sys_getgroups(unsigned long gidsetsize, unsigned long grouplist);
long linux_sys_setgroups(unsigned long gidsetsize, unsigned long grouplist);

// ── mmap / mprotect / munmap (also exposed from core/syscalls/mmap.d) ─────
long sys_mmap(uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags, uint64_t fd, uint64_t offset);
long sys_munmap(uint64_t addr, uint64_t len);
long sys_mprotect(uint64_t addr, uint64_t len, uint64_t prot);

#endif /* D_EXPORTS_H */
