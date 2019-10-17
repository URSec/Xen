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

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/shared.h>
#include <xen/softirq.h>
#include <asm/current.h>
#include <asm/hypercall.h>
#include <asm/irq.h>
#include <asm/processor.h>
#include <asm/regs.h>

#include <sva/interrupt.h>
#include <sva/state.h>

extern void sva_cpu_user_regs(struct cpu_user_regs *regs,
                              unsigned long *fs_base,
                              unsigned long *gs_base);
extern void sva_icontext(struct cpu_user_regs *regs,
                              unsigned long *fs_base,
                              unsigned long *gs_base);

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

static void test_events(struct cpu_user_regs *regs, struct vcpu *curr)
{
    local_irq_disable();

    if (softirq_pending(smp_processor_id())) {
        local_irq_enable();
        do_softirq();
        return test_events(regs, curr);
    }
    if (curr->arch.pv.trap_bounce.flags & TBF_EXCEPTION) {
        local_irq_enable();
        // TODO
        BUG();
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
