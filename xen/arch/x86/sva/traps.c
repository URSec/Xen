/******************************************************************************
 * arch/x86/sva/traps.c
 *
 * Copyright (c) The University of Rochester, 2019.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/guest_access.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/shared.h>
#include <xen/softirq.h>
#include <asm/current.h>
#include <asm/domain.h>
#include <asm/hypercall.h>
#include <asm/irq.h>
#include <asm/processor.h>
#include <asm/regs.h>

#include <sva/interrupt.h>
#include <sva/invoke.h>
#include <sva/state.h>

extern void sva_cpu_user_regs(struct cpu_user_regs *regs,
                              unsigned long *fs_base,
                              unsigned long *gs_base);
extern void sva_icontext(struct cpu_user_regs *regs,
                              unsigned long *fs_base,
                              unsigned long *gs_base);

static void make_bounce_frame(struct cpu_user_regs *regs, struct vcpu *curr,
                              struct trap_bounce *tb);
static void test_events(struct cpu_user_regs *regs, struct vcpu *curr);
static void _ret_from_intr_sva(struct cpu_user_regs *regs);

void copy_regs_from_sva(struct cpu_user_regs *regs)
{
    if (sva_was_privileged()) {
        sva_cpu_user_regs(regs, NULL, NULL);
    } else {
        struct cpu_info *cpu_info = get_cpu_info();
        sva_cpu_user_regs(regs, &cpu_info->guest_fs_base,
                          &cpu_info->guest_gs_base);
    }
}

void copy_regs_to_sva(struct cpu_user_regs *regs)
{
    if (!guest_mode(regs)) {
        sva_icontext(regs, NULL, NULL);
    } else {
        ASSERT((regs->ss & ~0x3) != 0);
        struct cpu_info *cpu_info = get_cpu_info();
        sva_icontext(regs, &cpu_info->guest_fs_base, &cpu_info->guest_gs_base);
    }
}

void do_trap_sva_shim(unsigned int vector)
{
    ASSERT(vector < 32 && vector != 14);

    struct cpu_user_regs _regs;
    struct cpu_user_regs *regs =
        sva_was_privileged() ? &_regs : guest_cpu_user_regs();

    copy_regs_from_sva(regs);
    if (sva_iunwind()) {
        /*
         * Regs changed by unwind; recopy them.
         */
        copy_regs_from_sva(regs);
        _ret_from_intr_sva(regs);
    } else {
        local_irq_enable();
        exception_table[vector](regs);
        _ret_from_intr_sva(regs);
    }
}

void do_page_fault_sva_shim(unsigned int vector, void *fault_addr)
{
    ASSERT(vector == 14);

    struct cpu_user_regs _regs;
    struct cpu_user_regs *regs =
        sva_was_privileged() ? &_regs : guest_cpu_user_regs();

    copy_regs_from_sva(regs);
    if (sva_iunwind()) {
        /*
         * Regs changed by unwind; recopy them.
         */
        copy_regs_from_sva(regs);
        _ret_from_intr_sva(regs);
    } else {
        local_irq_enable();
        exception_table[vector](regs);
        _ret_from_intr_sva(regs);
    }
}

void do_intr_sva_shim(unsigned int vector)
{
    ASSERT(vector >= 32 && vector < 256);

    struct cpu_user_regs _regs;
    struct cpu_user_regs *regs =
        sva_was_privileged() ? &_regs : guest_cpu_user_regs();

    copy_regs_from_sva(regs);
    do_IRQ(regs);
    _ret_from_intr_sva(regs);
}

void sva_syscall(void)
{
    struct vcpu *curr = current;
    struct cpu_user_regs *regs = guest_cpu_user_regs();

    local_irq_enable();

    copy_regs_from_sva(regs);
    if (curr->arch.flags & TF_kernel_mode) {
        pv_hypercall(regs);
    } else {
        struct trap_bounce *tb = &curr->arch.pv.trap_bounce;

        if (regs->cs == FLAT_USER_CS32 &&
            curr->arch.pv.syscall32_callback_eip != 0)
        {
            tb->eip = curr->arch.pv.syscall32_callback_eip;
        } else {
            tb->eip = curr->arch.pv.syscall_callback_eip;
        }
        if (curr->arch.vgc_flags & VGCF_syscall_disables_events) {
            tb->flags = TBF_INTERRUPT;
        } else {
            tb->flags = 0;
        }

        make_bounce_frame(regs, curr, tb);
        regs->eflags &= ~X86_EFLAGS_DF;
    }
    _ret_from_intr_sva(regs);
}

static void make_bounce_frame(struct cpu_user_regs *regs, struct vcpu *curr,
                              struct trap_bounce *tb)
{
    uintptr_t guest_rsp;
    uint16_t guest_cs = regs->cs;

    if (curr->arch.flags & TF_kernel_mode) {
        guest_rsp = regs->rsp;
        guest_cs &= ~0x3;
    } else {
        toggle_guest_mode(curr);
        guest_rsp = curr->arch.pv.kernel_sp;
    }

    /*
     * HACK: Since we are using SVA's interrupt context manipulation
     * intrinsics, we need to copy the current version of the interrupt context
     * back to SVA. This shouldn't be necessary, but currently is because we
     * are directly modifying the interrupt context in other parts of Xen.
     *
     * NB: This needs to be after the call to `toggle_guest_mode` in order to
     * properly update the guest's `%gs.base`.
     */
    copy_regs_to_sva(regs);

    char bounce_frame[8 * sizeof(uint64_t)];
    uint64_t *cur = (uint64_t*)bounce_frame;

    /*
     * `%rcx` and `%r11`, specific to Xen bounce frames.
     */
    *cur++ = regs->rcx;
    *cur++ = regs->r11;

    /*
     * Error code (if applicable), same as a native x86 interrupt frame.
     */
    if (tb->flags & TBF_EXCEPTION_ERRCODE) {
        *cur++ = tb->error_code;
    }

    /*
     * Saved `%rip` and `%cs`, like native.
     */
    *cur++ = regs->rip;
    *(uint32_t*)cur = (uint32_t)guest_cs;

    /*
     * Saved upcall mask: Xen's version of `%eflags.IF`. We slot this in to the
     * high bytes of the saved %cs selector (which are unused in a native
     * interrupt frame).
     */
    *((uint32_t*)cur + 1) = vcpu_info(curr, evtchn_upcall_mask);
    cur++;

    /*
     * Saved `%rflags`, like native.
     */
    uint64_t new_rflags = regs->rflags & ~(X86_EFLAGS_IF|X86_EFLAGS_IOPL);
    if (!vcpu_info(curr, evtchn_upcall_mask)) {
        new_rflags |= X86_EFLAGS_IF;
    }
    if (VM_ASSIST(curr->domain, architectural_iopl)) {
        new_rflags |= curr->arch.pv.iopl;
    }
    *cur++ = new_rflags;

    /*
     * Saved `%rsp` and `%ss`, like native.
     */
    *cur++ = regs->rsp;
    *cur++ = regs->ss;

    size_t bf_size = (char*)cur - bounce_frame;
    if (unlikely(!sva_ialloca_newstack(guest_rsp, FLAT_KERNEL_SS,
                                       bounce_frame, bf_size, 4)))
    {
    bad_ialloca:
        show_page_walk(guest_rsp);
        if (PFN_DOWN(guest_rsp) != PFN_DOWN(guest_rsp - bf_size)) {
            /*
             * We don't know which part of the ialloca failed, so show the page
             * walk for both guest stack pages.
             */
            show_page_walk(guest_rsp - bf_size);
        }
        asm_domain_crash_synchronous((uintptr_t)&&bad_ialloca);
    }

    /*
     * HACK: See above.
     */
    copy_regs_from_sva(regs);

    /*
     * Disable events if this bounce frame is interrupt-like.
     */
    vcpu_info(curr, evtchn_upcall_mask) |= !!(tb->flags & TBF_INTERRUPT);

    /*
     * Set up the guest to execute the trap handler when we return to it.
     */
    regs->entry_vector |= TRAP_syscall;
    regs->eflags &= ~(X86_EFLAGS_AC | X86_EFLAGS_VM | X86_EFLAGS_RF |
                      X86_EFLAGS_NT | X86_EFLAGS_TF);
    regs->cs = FLAT_KERNEL_CS;
    if (unlikely(tb->eip == 0)) {
    no_trap_handler:
        asm_domain_crash_synchronous((uintptr_t)&&no_trap_handler);
    }
    regs->rip = tb->eip;
}

static void test_events(struct cpu_user_regs *regs, struct vcpu *curr)
{
    local_irq_disable();

    if (softirq_pending(smp_processor_id())) {
        local_irq_enable();
        do_softirq();
        return test_events(regs, curr);
    }

    struct trap_bounce *tb = &curr->arch.pv.trap_bounce;
    if (tb->flags & TBF_EXCEPTION) {
        local_irq_enable();
        make_bounce_frame(regs, curr, tb);
        tb->flags = 0;
        return test_events(regs, curr);
    }

    if (curr->mce_pending) {
        // TODO
        BUG();
    }
    if (curr->nmi_pending) {
        // TODO
        BUG();
    }

    if (vcpu_info(curr, evtchn_upcall_pending) &&
        !vcpu_info(curr, evtchn_upcall_mask))
    {
        local_irq_enable();
        tb->eip = curr->arch.pv.event_callback_eip;
        tb->flags = TBF_INTERRUPT;
        make_bounce_frame(regs, curr, tb);
        return test_events(regs, curr);
    }
}

static void _ret_from_intr_sva(struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;

    if (guest_mode(regs)) {
        test_events(regs, curr);

        if (get_cpu_info()->pv_cr3 != 0) {
            BUG();
        }
    }

    copy_regs_to_sva(regs);
}

void ret_from_intr_sva(void)
{
    _ret_from_intr_sva(guest_cpu_user_regs());
}

void __init init_sva_traps(void)
{
    for (int i = 0; i < 32; ++i) {
        if (i == 14 /* Page fault */) {
            sva_register_memory_exception(i, do_page_fault_sva_shim);
        } else {
            sva_register_general_exception(i, do_trap_sva_shim);
        }
    }

    for (int i = 32; i < 256; ++i) {
        sva_register_interrupt(i, do_intr_sva_shim);
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
