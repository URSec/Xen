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
#include <sva/state.h>

/* Hacky; we should make a builtin for this */
#define current_rip() ({                                    \
    uintptr_t __rip;                                        \
    asm volatile ("leaq 1f(%%rip), %0; 1:" : "=r"(__rip));  \
    __rip;                                                  \
})

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
    exception_table[vector](regs);
    _ret_from_intr_sva(regs);
}

void do_page_fault_sva_shim(unsigned int vector, void *fault_addr)
{
    ASSERT(vector == 14);

    struct cpu_user_regs _regs;
    struct cpu_user_regs *regs =
        sva_was_privileged() ? &_regs : guest_cpu_user_regs();

    copy_regs_from_sva(regs);
    exception_table[vector](regs);
    _ret_from_intr_sva(regs);
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
    local_irq_enable();

    copy_regs_from_sva(guest_cpu_user_regs());
    if (current->arch.flags & TF_kernel_mode) {
        pv_hypercall(guest_cpu_user_regs());
    } else {
        // TODO
        BUG();
    }
    _ret_from_intr_sva(guest_cpu_user_regs());
}

static void store_guest_stack(uintptr_t rsp, void *val, size_t size) {
    if (unlikely(copy_to_user((void*)rsp, val, size) != 0)) {
        clac();
        show_page_walk(rsp);
        asm_domain_crash_synchronous(current_rip());
    }
}

static void make_bounce_frame(struct cpu_user_regs *regs, struct vcpu *curr,
                              struct trap_bounce *tb)
{
    struct bounce_frame {
        uint64_t rcx;
        uint64_t r11;
        uint64_t error_code;
        uint64_t rip;
        uint16_t cs;
        uint16_t _pad;
        uint32_t saved_upcall_mask;
        uint64_t rflags;
        uint64_t rsp;
        uint64_t ss;
    };

    uintptr_t guest_rsp;
    uint16_t guest_cs = regs->cs;

    if (curr->arch.flags & TF_kernel_mode) {
        guest_rsp = regs->rsp;
        guest_cs &= ~0x3;
    } else {
        toggle_guest_mode(curr);
        guest_rsp = curr->arch.pv.kernel_sp;
    }
    guest_rsp &= ~0xfUL; // Align the stack

    if (unlikely(HYPERVISOR_VIRT_START < guest_rsp &&
                 guest_rsp < HYPERVISOR_VIRT_END + sizeof(struct bounce_frame)))
    {
        asm_domain_crash_synchronous(current_rip());
    }

    struct bounce_frame bf = {
        .rcx = regs->rcx,
        .r11 = regs->r11,
        .error_code = tb->flags & TBF_EXCEPTION_ERRCODE ? tb->error_code : 0,
        .rip = regs->rip,
        .cs = guest_cs,
        ._pad = 0,
        .saved_upcall_mask = vcpu_info(curr, evtchn_upcall_mask),
        .rflags = regs->rflags & ~(X86_EFLAGS_IF|X86_EFLAGS_IOPL),
        .rsp = regs->rsp,
        .ss = regs->ss,
    };

    bf.rflags |= !vcpu_info(curr, evtchn_upcall_mask) ? X86_EFLAGS_IF : 0;
    bf.rflags |= VM_ASSIST(curr->domain, architectural_iopl) ? curr->arch.pv.iopl : 0;

    vcpu_info(curr, evtchn_upcall_mask) |= !!(tb->flags & TBF_INTERRUPT);

#define STORE_GUEST_STACK(val) do {                         \
        guest_rsp -= sizeof(val);                           \
        store_guest_stack(guest_rsp, &(val), sizeof(val));  \
    } while (0)

    stac();
    STORE_GUEST_STACK(bf.ss);
    STORE_GUEST_STACK(bf.rsp);
    STORE_GUEST_STACK(bf.rflags);
    STORE_GUEST_STACK(bf.saved_upcall_mask);
    //guest_rsp -= sizeof(bf._pad); // No need to store padding
    STORE_GUEST_STACK(bf._pad);
    STORE_GUEST_STACK(bf.cs);
    STORE_GUEST_STACK(bf.rip);
    if (tb->flags & TBF_EXCEPTION_ERRCODE) {
        STORE_GUEST_STACK(bf.error_code);
    }
    STORE_GUEST_STACK(bf.r11);
    STORE_GUEST_STACK(bf.rcx);
    clac();

#undef STORE_GUEST_STACK

    regs->entry_vector |= TRAP_syscall;
    regs->eflags &= ~(X86_EFLAGS_AC | X86_EFLAGS_VM | X86_EFLAGS_RF |
                      X86_EFLAGS_NT | X86_EFLAGS_TF);
    regs->ss = FLAT_KERNEL_SS;
    regs->rsp = guest_rsp;
    regs->cs = FLAT_KERNEL_CS;
    if (unlikely(tb->eip == 0)) {
        asm_domain_crash_synchronous(current_rip());
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
        // TODO
        BUG();
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
