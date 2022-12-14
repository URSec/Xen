/******************************************************************************
 * current.h
 * 
 * Information structure that lives at the bottom of the per-cpu Xen stack.
 */

#ifndef __X86_CURRENT_H__
#define __X86_CURRENT_H__

#include <xen/percpu.h>
#include <public/xen.h>
#include <asm/page.h>

/*
 * Xen's cpu stacks are 8 pages (8-page aligned), arranged as:
 *
 * 7 - Primary stack (with a struct cpu_info at the top)
 * 6 - Primary stack
 * 5 - Optionally not present (MEMORY_GUARD)
 * 4 - Unused; optionally not present (MEMORY_GUARD)
 * 3 - Unused; optionally not present (MEMORY_GUARD)
 * 2 - MCE IST stack
 * 1 - NMI IST stack
 * 0 - Double Fault IST stack
 */

/*
 * Identify which stack page the stack pointer is on.  Returns an index
 * as per the comment above.
 */
static inline unsigned int get_stack_page(unsigned long sp)
{
    return (sp & (STACK_SIZE-1)) >> PAGE_SHIFT;
}

struct vcpu;

struct cpu_info {
    struct cpu_user_regs guest_cpu_user_regs;
    unsigned int processor_id;
    struct vcpu *current_vcpu;
    unsigned long per_cpu_offset;
    unsigned long cr4;
    /*
     * Of the two following fields the latter is being set to the CR3 value
     * to be used on the given pCPU for loading whenever 64-bit PV guest
     * context is being entered. A value of zero indicates no setting of CR3
     * is to be performed.
     * The former is the value to restore when re-entering Xen, if any. IOW
     * its value being zero means there's nothing to restore.
     */
    unsigned long xen_cr3;
    unsigned long pv_cr3;

    /* See asm-x86/spec_ctrl_asm.h for usage. */
    unsigned int shadow_spec_ctrl;
    uint8_t      xen_spec_ctrl;
    uint8_t      spec_ctrl_flags;

    /*
     * The following field controls copying of the L4 page table of 64-bit
     * PV guests to the per-cpu root page table on entering the guest context.
     * If set the L4 page table is being copied to the root page table and
     * the field will be reset.
     */
    bool         root_pgt_changed;

    /*
     * use_pv_cr3 is set in case the value of pv_cr3 is to be written into
     * CR3 when returning from an interrupt. The main use is when returning
     * from a NMI or MCE to hypervisor code where pv_cr3 was active.
     */
    bool         use_pv_cr3;

#ifdef CONFIG_SVA
    /*
     * SVA uses the %fs and %gs bases, so we need to store the guest values on
     * entry to Xen and restore them on exit. */
    unsigned long guest_fs_base;
    unsigned long guest_gs_base;
    unsigned long guest_gs_shadow;
#else
    unsigned long __pad;
    /* get_stack_bottom() must be 16-byte aligned */
#endif
};

static inline struct cpu_info *get_cpu_info(void)
{
#ifdef CONFIG_SPLIT_STACK
    unsigned long sp;
    asm ( "mov %%r15, %0" : "=r" (sp) );
#else
#ifdef __clang__
    /* Clang complains that sp in the else case is not initialised. */
    unsigned long sp;
    asm ( "mov %%rsp, %0" : "=r" (sp) );
#else
    register unsigned long sp asm("rsp");
#endif
#endif

    return (struct cpu_info *)((sp | (STACK_SIZE - 1)) + 1) - 1;
}

#define get_current()         (get_cpu_info()->current_vcpu)
#define set_current(vcpu)     (get_cpu_info()->current_vcpu = (vcpu))
#define current               (get_current())

#define get_processor_id()    (get_cpu_info()->processor_id)
#define set_processor_id(id)  do {                                      \
    struct cpu_info *ci__ = get_cpu_info();                             \
    ci__->per_cpu_offset = __per_cpu_offset[ci__->processor_id = (id)]; \
} while (0)

#define guest_cpu_user_regs() (&get_cpu_info()->guest_cpu_user_regs)

/*
 * Get the bottom-of-stack, as stored in the per-CPU TSS. This actually points
 * into the middle of cpu_info.guest_cpu_user_regs, at the section that
 * precisely corresponds to a CPU trap frame.
 */
#define get_stack_bottom()                      \
    ((unsigned long)&get_cpu_info()->guest_cpu_user_regs.es)

/*
 * Get the reasonable stack bounds for stack traces and stack dumps.  Stack
 * dumps have a slightly larger range to include exception frames in the
 * printed information.  The returned word is inside the interesting range.
 */
unsigned long get_stack_trace_bottom(unsigned long sp);
unsigned long get_stack_dump_bottom (unsigned long sp);

#ifndef CONFIG_SVA

#ifdef CONFIG_LIVEPATCH
# define CHECK_FOR_LIVEPATCH_WORK "call check_for_livepatch_work; endbr64;"
#else
# define CHECK_FOR_LIVEPATCH_WORK ""
#endif

#define reset_stack_and_jump(__fn)                                      \
    ({                                                                  \
        __asm__ __volatile__ (                                          \
            "mov %0,%%"__OP"sp;"                                        \
            CHECK_FOR_LIVEPATCH_WORK                                      \
             "jmp %c1"                                                  \
            : : "r" (guest_cpu_user_regs()), "i" (__fn) : "memory" );   \
        unreachable();                                                  \
    })

#else

static inline void noreturn reset_stack_and_jump(void(*fn)(void)) {
    extern void noreturn sva_reinit_stack(void (*func)(void));

    // TODO: check for livepatch work
    sva_reinit_stack(fn);
}

#endif

/*
 * Which VCPU's state is currently running on each CPU?
 * This is not necesasrily the same as 'current' as a CPU may be
 * executing a lazy state switch.
 */
DECLARE_PER_CPU(struct vcpu *, curr_vcpu);

#endif /* __X86_CURRENT_H__ */
