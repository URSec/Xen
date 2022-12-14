/*
 * include/asm-i386/i387.h
 *
 * Copyright (C) 1994 Linus Torvalds
 *
 * Pentium III FXSR, SSE support
 * General FPU state handling cleanups
 *	Gareth Hughes <gareth@valinux.com>, May 2000
 */

#ifndef __ASM_I386_I387_H
#define __ASM_I386_I387_H

#include <xen/types.h>
#include <xen/percpu.h>

#ifdef CONFIG_SVA
#include <xen/sched.h> /* For struct vcpu, used in vcpu_init_fpu() */
#endif

/* Byte offset of the stored word size within the FXSAVE area/portion. */
#define FPU_WORD_SIZE_OFFSET 511

struct ix87_env {
    uint16_t fcw, _res0;
    uint16_t fsw, _res1;
    uint16_t ftw, _res2;
    uint32_t fip;
    uint16_t fcs;
    uint16_t fop;
    uint32_t fdp;
    uint16_t fds, _res6;
};

struct xsave_struct;

#ifdef CONFIG_SVA
/*
 * FPU state is handled by SVA. Provide stubs for Xen FPU state functions.
 */

static inline void vcpu_restore_fpu_nonlazy(struct vcpu *__maybe_unused v,
                                            bool __maybe_unused need_stts)
{ }

static inline void vcpu_restore_fpu_lazy(struct vcpu *__maybe_unused v)
{ }

static inline void vcpu_save_fpu(struct vcpu *__maybe_unused v)
{ }

static inline void save_fpu_enable(void)
{ }

static inline int vcpu_init_fpu(struct vcpu *__maybe_unused v)
{
    /*
     * SVA doesn't require most of the functionality that vcpu_init_fpu() is
     * responsible for, but it's responsible for initializing the vCPU's XCR0
     * and xcr0_accum values, so we need to do that here to make sure they're
     * not left as uninitialized junk.
     *
     * FIXME: this may not matter if/when we switch to having XCR0 "live"
     * fully on the SVA side instead of being copied to/from Xen on VM entry
     * and exit.
     */
    v->arch.xcr0 = 0;
    v->arch.xcr0_accum = 0;

    return 0;
}

static inline void vcpu_setup_fpu(struct vcpu *__maybe_unused v,
                    struct xsave_struct *__maybe_unused xsave_area,
                    const void *__maybe_unused data,
                    unsigned int __maybe_unused fcw_default)
{ }

static inline void vcpu_destroy_fpu(struct vcpu *__maybe_unused v)
{ }

#else
void vcpu_restore_fpu_nonlazy(struct vcpu *v, bool need_stts);
void vcpu_restore_fpu_lazy(struct vcpu *v);
void vcpu_save_fpu(struct vcpu *v);
void save_fpu_enable(void);

int vcpu_init_fpu(struct vcpu *v);
void vcpu_setup_fpu(struct vcpu *v, struct xsave_struct *xsave_area,
                    const void *data, unsigned int fcw_default);
void vcpu_destroy_fpu(struct vcpu *v);
#endif

#endif /* __ASM_I386_I387_H */
