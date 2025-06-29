# Thread context switch for x86_64
.code64
.global switch_thread
.global restore_first

# void switch_thread(ThreadContext* old, ThreadContext* next)
# rdi = old, rsi = next
switch_thread:
    movq %rsp, 0(%rdi)
    movq %rbp, 8(%rdi)
    movq %rbx, 16(%rdi)
    movq %r12, 24(%rdi)
    movq %r13, 32(%rdi)
    movq %r14, 40(%rdi)
    movq %r15, 48(%rdi)

    movq 0(%rsi), %rsp
    movq 8(%rsi), %rbp
    movq 16(%rsi), %rbx
    movq 24(%rsi), %r12
    movq 32(%rsi), %r13
    movq 40(%rsi), %r14
    movq 48(%rsi), %r15
    ret

# void restore_first(ThreadContext* next)
restore_first:
    movq 0(%rdi), %rsp
    movq 8(%rdi), %rbp
    movq 16(%rdi), %rbx
    movq 24(%rdi), %r12
    movq 32(%rdi), %r13
    movq 40(%rdi), %r14
    movq 48(%rdi), %r15
    ret

