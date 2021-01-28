/*******************************************************************************
 * VMX entry/exit code using SVA intrinsics instead of raw VMX assembly
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

#include <xen/lib.h> /* For panic() */

/* Gives us the get_current() macro to get pointer to active vCPU descriptor */
#include <asm/current.h>

#include <asm/hvm/vmx/vmx.h>
#include <xen/softirq.h>
#include <asm/xstate.h> /* For XSTATE_FP_SSE macro */

#include <asm/bug.h>

#include <sva/vmx_intrinsics.h>

/*
 * In non-SVA Xen, these functions are only ever called by the assembly code
 * in arch/x86/hvm/vmx/entry.S, so they are not declared in any header file.
 * We'll just declare them locally for this file to keep things simple.
 */
void vmx_enter_realmode(struct cpu_user_regs *regs);
bool vmx_vmenter_helper(const struct cpu_user_regs *regs);
void vmx_vmexit_handler(struct cpu_user_regs *regs);
void vmx_vmentry_failure(void);

/*
 * Function: vmx_do_vmentry_sva()
 *
 * Description:
 *  C function for VM entry/exit that calls SVA intrinsics instead of Xen's
 *  native VMX assembly.
 *
 *  Declared in header include/asm-x86/hvm/vmx/vmx.h so that it can be called
 *  by vmx_do_resume() (in arch/x86/hvm/vmx/vmcs.c) via
 *  reset_stack_and_jump().
 *
 *  Use in lieu of vmx_asm_do_vmentry() (an assembly function defined in
 *  arch/x86/hvm/vmx/entry.S) in the SVA config.
 *
 * Preconditions:
 *  * A virtual machine/VMCS should be currently loaded on the processor
 *    (with the sva_loadvm() intrinsic).
 *
 * High-level logic:
 *  This function will enter the currently loaded VM, handle any VM exits,
 *  and re-enter the same VM in an infinite loop.
 *
 *  Similar to Xen's native assembly code for this, each time we are about to
 *  enter the VM, we will check to see if Xen has queued any pending "soft
 *  IRQ" events for this vCPU. If so, we will process them by calling the Xen
 *  function do_softirq().
 *
 *  Xen makes scheduling decisions through this soft IRQ mechanism; if/when
 *  it decides that it wants to run a different vCPU instead of the one we
 *  are currently running, that do_softirq() call will ultimately call
 *  vmx_do_resume(), which will unload the current VMCS, load a different
 *  one, and call vmx_do_vmentry_sva() afresh using reset_stack_and_jump().
 *  (Alternatively, depending on what the scheduler has decided to do, Xen
 *  might reset_stack_and_jump() into an idle loop or into the VM entry/exit
 *  loop function for PV guests. vmx_do_vmentry_sva() only handles HVM/PVH
 *  guests, i.e. those utilizing VMX hardware support.)
 *
 *  Such a stack reset is the mechanism by which the VM entry/exit infinite
 *  loop is ultimately terminated.
 */
void vmx_do_vmentry_sva(void)
{
    /*
     * Get a pointer to Xen's vCPU descriptor for the vCPU currently active
     * on this physical CPU.
     *
     * get_current() is a macro for get_cpu_info()->current_vcpu, which uses
     * inline assembly to access Xen's per-CPU data structures that lives at
     * the top of Xen's stack. (This is a hack which we allow in our "impure"
     * partial port of Xen to SVA; "eventually" we'll want to modify Xen to
     * use a cleaner method of maintaining per-CPU data, such as the C
     * language's official thread-local storage support which is supported by
     * Clang.)
     */
    struct vcpu *current_vcpu = get_current();

    /*
     * Get a pointer to the structure that Xen uses to store the guest's
     * register state when it's not running.
     *
     * This is a macro, similar to get_current(), which finds Xen's per-CPU
     * data structure at the top of the stack and computes a pointer to the
     * guest_cpu_user_regs structure within it.
     */
    struct cpu_user_regs *guest_regs = guest_cpu_user_regs();

    /*
     * Determine the numeric identifier that SVA uses to refer to this vCPU.
     *
     * (NOTE: this is a temporary hack during porting; once we have fully
     * given control of the VMCS to SVA, Xen will no longer have a pointer to
     * the VMCS, but will use SVA's numeric identifier instead.)
     */
    int sva_vmid = sva_get_vmid_from_vmcs(current_vcpu->arch.hvm.vmx.vmcs_pa);

    /*
     * Run the guest vCPU and handle its VM exits in an infinite loop until
     * Xen breaks it by performing a context switch in our call to its soft
     * IRQ handler (do_softirq()).
     */
    while (1)
    {
        /*
         * Xen's native VM-entry assembly calls this here. I think it's
         * responsible for delivering interrupts to the guest when needed.
         * (It may also be responsible for other things related to guest
         * interrupts. Its comments are not especially helpful in
         * understanding its big-picture purpose.)
         */
        vmx_intr_assist();

        /*
         * Xen's native VM-entry assembly calls this here. It looks like it's
         * responsible for emulating VM entry/exit for a nested hypervisor
         * within the guest. (As far as I can tell, this isn't something SVA
         * needs to be concerned with as Xen will take care of "flattening"
         * the level-1 and level-2 VMCSes into ones that we can understand at
         * the host level.)
         */
        nvmx_switch_guest();

        /* Xen's native VM-entry assembly makes this assertion here. */
        ASSERT_NOT_IN_ATOMIC();

        /*
         * ***DISABLE INTERRUPTS***
         *
         * This ensures that no soft IRQs come in during the time window
         * between when we check the soft-IRQ-pending flag and VM entry.
         *
         * Note that in the event we find that a soft IRQ *is* pending, we
         * will need to re-enable interrupts before calling do_softirq().
         * This is fine since after we return from do_softirq(), we will skip
         * the rest of this loop and start it afresh, giving us the chance to
         * handle any further soft IRQs that might have come in.
         */
        local_irq_disable();

        /*
         * If Xen has queued any soft IRQs for this processor, handle them
         * before VM entry.
         *
         * This may result in Xen context switching to another vCPU, in which
         * case the call to do_softirq() will not return, but instead wipe
         * out the stack with reset_stack_and_jump() to call
         * vmx_do_vmentry_sva() (or an idle loop, or the PV guest entry
         * function) afresh.
         */
        unsigned cpu = smp_processor_id();
        BUG_ON(cpu != current_vcpu->processor); /* make sure I'm understanding this right */
        unsigned softirq_is_pending = softirq_pending(cpu);
        if ( softirq_is_pending )
        {
            /* Re-enable interrupts. */
            local_irq_enable();

            do_softirq();

            /*
             * After processing the soft IRQ, start the loop afresh since
             * another soft IRQ might have come in that we'll need to address
             * before proceeding to VM entry.
             */
            continue;
        }

        /*
         * If Xen has marked this vCPU to emulate instead of running natively
         * on its next instruction, call the real-mode emulator.
         *
         * (It appears that Xen only uses this "emulate" flag for real-mode
         * guests on hardware that doesn't support the "unrestricted guest"
         * feature, i.e. can't run real-mode guests natively. Even then, Xen
         * will try to "fake" real mode using virtual-8086 mode, and only
         * fall back to the emulator when it gets into a situation that it
         * can't fake.)
         */
        if ( current_vcpu->arch.hvm.vmx.vmx_emulate )
        {
            /* Re-enable interrupts. */
            local_irq_enable();

            vmx_realmode(guest_regs);

            /*
             * After running the emulator, start the loop afresh since a soft
             * IRQ might have come in that we'll need to address before
             * proceeding to VM entry.
             */
            continue;
        }

        /*
         * If the vCPU we are about to enter will be in real mode and the
         * hardware doesn't support the "unrestricted guest" feature (i.e.
         * can't run real-mode guests natively), Xen will try to "fake" real
         * mode using virtual-8086 mode.
         *
         * The "vmx_realmode" flag indicates that this "fake" real mode is
         * needed. (As far as I can tell, despite its name, this flag is
         * *not* set for guests entering into real mode if the hardware
         * supports executing them natively. Intel's unrestricted guest
         * feature is a relatively recent addition (Broadwell) so the flag
         * probably predates it, hence its misleading name.)
         */
        if ( current_vcpu->arch.hvm.vmx.vmx_realmode )
        {
            /*
             * If any of the vCPU's segments have been marked as unsafe to
             * use in virtual 8086 mode, fall back to the real-mode emulator
             * instead of peforming native VM entry.
             */
            if ( current_vcpu->arch.hvm.vmx.vm86_segment_mask != 0 )
            {
                /* Re-enable interrupts. */
                local_irq_enable();

                vmx_realmode(guest_regs);

                /*
                 * After running the emulator, start the loop afresh since a
                 * soft IRQ might have come in that we'll need to address
                 * before attempting VM entry again.
                 */
                continue;
            }

            /*
             * Call Xen's helper function for entering "fake" real mode via
             * virtual-8086 mode.
             *
             * This function's only responsibility (at least in Xen 4.12)
             * seems to be to fudge the guest's RFLAGS to set the VM bit
             * (enabling virtual-8086 mode) and IOPL=3. It stashes the
             * original guest RFLAGS in
             * current_vcpu->arch.hvm.vmx.vm86_saved_eflags.  Xen's VM-exit
             * handler function, vmx_vmexit_handler(), will put this saved
             * RFLAGS back into place after VM exit.
             *
             * NOTE: we call this function with interrupts *disabled*. (Not
             * that the function is doing anything complicated enough to
             * care, but it seems best to document such things...)
             */
            vmx_enter_realmode(guest_regs);
        }

        /*
         * Call Xen's VM entry helper (some C code that it runs before VMX VM
         * entry) in preparation for VM entry.
         *
         * NOTE: we call this function with interrupts *disabled*.
         */
        if ( !vmx_vmenter_helper(guest_regs) )
        {
            /*
             * vmx_vmenter_helper() returned false, indicating that the VM
             * entry needs to be restarted.
             *
             * As far as I can tell, the only scenario in which this will be
             * true has something to do with needing to update a shadow EPTP
             * for a nested hypervisor, which according to a comment in
             * vmx_vmenter_helper() can't be done with interrupts disabled.
             */

            /* Re-enable interrupts. */
            local_irq_enable();
            /* Restart the VM entry. */
            continue;
        }

        /*
         * Copy the guest's non-VMCS-resident register state that will be
         * restored on VM entry from Xen's guest_cpu_user_regs struct to
         * SVA's internal VM descriptor.
         */
        sva_setvmreg(sva_vmid, VM_REG_RAX, guest_regs->rax);
        sva_setvmreg(sva_vmid, VM_REG_RBX, guest_regs->rbx);
        sva_setvmreg(sva_vmid, VM_REG_RCX, guest_regs->rcx);
        sva_setvmreg(sva_vmid, VM_REG_RDX, guest_regs->rdx);
        sva_setvmreg(sva_vmid, VM_REG_RBP, guest_regs->rbp);
        sva_setvmreg(sva_vmid, VM_REG_RSI, guest_regs->rsi);
        sva_setvmreg(sva_vmid, VM_REG_RDI, guest_regs->rdi);
        sva_setvmreg(sva_vmid, VM_REG_R8,  guest_regs->r8);
        sva_setvmreg(sva_vmid, VM_REG_R9,  guest_regs->r9);
        sva_setvmreg(sva_vmid, VM_REG_R10, guest_regs->r10);
        sva_setvmreg(sva_vmid, VM_REG_R11, guest_regs->r11);
        sva_setvmreg(sva_vmid, VM_REG_R12, guest_regs->r12);
        sva_setvmreg(sva_vmid, VM_REG_R13, guest_regs->r13);
        sva_setvmreg(sva_vmid, VM_REG_R14, guest_regs->r14);
        sva_setvmreg(sva_vmid, VM_REG_R15, guest_regs->r15);
        sva_setvmreg(sva_vmid, VM_REG_CR2, current_vcpu->arch.hvm.guest_cr[2]);
        /*
         * If the guest's XCR0 is set to all zeroes (which is what Xen sets
         * it to when initializing a vCPU with "fresh" state), force the x87
         * and SSE bits (bits 0 and 1) on. (Xen's macro XSTATE_FP_SSE
         * corresponds to the OR of those two bits.)
         *
         * The x87 bit must be set in order to avoid getting a general
         * protection fault when SVA tries to load this value into XCR0 in
         * non-root mode before VM entry. Vanilla Xen's behavior is to force
         * the SSE bit on as well, so we will imitate that here to avoid
         * surprising other parts of the codebase.
         *
         * I'm not exactly sure why Xen does this here instead of just
         * initializing the "fresh" state to have (only) these two bits set.
         * It may have something to do with the interplay between XCR0 and
         * Xen's "XCR0 accumulator" variable (v->arch.xcr0_accum), which
         * tracks all the X-state features that have *ever* been used by this
         * vCPU since its last reset. Forcing these bits on at this late
         * stage instead of initializing them that way means that they don't
         * get set in xcr0_accum until the guest actually chooses to load an
         * XCR0 value that enables them.
         */
        uint64_t guest_xcr0 = current_vcpu->arch.xcr0 | XSTATE_FP_SSE;
        sva_setvmreg(sva_vmid, VM_REG_XCR0, guest_xcr0);
        sva_setvmreg(sva_vmid, VM_REG_MSR_XSS, current_vcpu->arch.hvm.msr_xss);
        sva_setvmreg(sva_vmid, VM_REG_MSR_FMASK, current_vcpu->arch.hvm.vmx.sfmask);
        sva_setvmreg(sva_vmid, VM_REG_MSR_STAR, current_vcpu->arch.hvm.vmx.star);
        sva_setvmreg(sva_vmid, VM_REG_MSR_LSTAR, current_vcpu->arch.hvm.vmx.lstar);
        /* Note: we don't need to copy CSTAR since it's only relevant on AMD
         * hardware (Intel never supported SYSCALL in 32-bit mode). Xen
         * handles VM exits for attempted reads and writes to it by the guest
         * but it never actually installs it on the physical hardware; it
         * only tracks the written value in struct vcpu so that it can
         * emulate reads consistent with writes. */
        sva_setvmreg(sva_vmid, VM_REG_GS_SHADOW, current_vcpu->arch.hvm.vmx.shadow_gs);


        /*
         * Finally, perform VMX VM entry to run the vCPU natively on the
         * processor.
         *
         * The call to sva_runvm() will run until a VM exit occurs and return
         * here.
         */
        /* FIXME: simplify sva_launchvm() and sva_resumevm() to just
         * sva_runvm() (as it is in the paper) since SVA has to keep track of
         * whether or not the VM has been launched for correctness purposes
         * anyway.
         *
         * (OK, so technically I'm not sure SVA needs to keep track of it for
         * *correctness*, since there's not really any harm in letting Xen do
         * the wrong one - it just results in a VM entry failure. Still, it's
         * a "nice thing to have" since it lets us simplify SVA's interface.)
         */
        int vmrun_retval;
        if ( !current_vcpu->arch.hvm.vmx.launched )
            vmrun_retval = sva_launchvm();
        else
            vmrun_retval = sva_resumevm();


        /*
         * Copy the guest's non-VMCS-resident register state that was saved
         * on VM exit by SVA into Xen's guest_cpu_user_regs struct.
         */
        guest_regs->rax = sva_getvmreg(sva_vmid, VM_REG_RAX);
        guest_regs->rbx = sva_getvmreg(sva_vmid, VM_REG_RBX);
        guest_regs->rcx = sva_getvmreg(sva_vmid, VM_REG_RCX);
        guest_regs->rdx = sva_getvmreg(sva_vmid, VM_REG_RDX);
        guest_regs->rbp = sva_getvmreg(sva_vmid, VM_REG_RBP);
        guest_regs->rsi = sva_getvmreg(sva_vmid, VM_REG_RSI);
        guest_regs->rdi = sva_getvmreg(sva_vmid, VM_REG_RDI);
        guest_regs->r8  = sva_getvmreg(sva_vmid, VM_REG_R8);
        guest_regs->r9  = sva_getvmreg(sva_vmid, VM_REG_R9);
        guest_regs->r10 = sva_getvmreg(sva_vmid, VM_REG_R10);
        guest_regs->r11 = sva_getvmreg(sva_vmid, VM_REG_R11);
        guest_regs->r12 = sva_getvmreg(sva_vmid, VM_REG_R12);
        guest_regs->r13 = sva_getvmreg(sva_vmid, VM_REG_R13);
        guest_regs->r14 = sva_getvmreg(sva_vmid, VM_REG_R14);
        guest_regs->r15 = sva_getvmreg(sva_vmid, VM_REG_R15);
        current_vcpu->arch.hvm.guest_cr[2] = sva_getvmreg(sva_vmid, VM_REG_CR2);
        current_vcpu->arch.xcr0 = sva_getvmreg(sva_vmid, VM_REG_XCR0);
        current_vcpu->arch.hvm.msr_xss = sva_getvmreg(sva_vmid, VM_REG_MSR_XSS);
        current_vcpu->arch.hvm.vmx.sfmask = sva_getvmreg(sva_vmid, VM_REG_MSR_FMASK);
        current_vcpu->arch.hvm.vmx.star = sva_getvmreg(sva_vmid, VM_REG_MSR_STAR);
        current_vcpu->arch.hvm.vmx.lstar = sva_getvmreg(sva_vmid, VM_REG_MSR_LSTAR);
        current_vcpu->arch.hvm.vmx.shadow_gs = sva_getvmreg(sva_vmid, VM_REG_GS_SHADOW);

        /*
         * If sva_runvm() returned due to a nominal VM exit, call Xen's
         * VM-exit handler.
         *
         * Otherwise, VM entry failed; call Xen's VM-entry failure function.
         */
        if ( vmrun_retval == 0 ) /* Nominal VM exit */
        {
            /*
             * Mark the vCPU as "launched" so that Xen will know to use
             * sva_resumevm() instead of sva_launchvm() next time it tries to
             * re-enter this vCPU.
             *
             * FIXME: this should in theory become moot once we unify
             * sva_launchvm() and sva_resumevm() to sva_runvm() (since SVA
             * will be making the launch vs. resume decision based on its
             * internal tracking of the launch state which it's doing already
             * as a sanity check). (It looks like Xen isn't using this value
             * anywhere else except in debug printouts.)
             */
            current_vcpu->arch.hvm.vmx.launched = 1;

            /*
             * The hardware clears MSR_DEBUGCTL on VM exit. Reinstate it if
             * debugging Xen.
             *
             * (This uses inline assembly, and is a hack necessitated by
             * SVA's current lack of intrinsic support for the processor's
             * hardware debugging features.)
             */
            /* TODO */

            /* TODO: Xen also does something involving "restore_lbr" here;
             * it's wrapped in a macro called "ALTERNATIVE". Figure out what
             * this does and if/how we need to imitate it here. */

            /*
             * Call Xen's C function for VM exit handling.
             *
             * NOTE: we must call this with interrupts disabled.
             * ***IT WILL RE-ENABLE INTERRUPTS*** during its execution
             * (specifically, after it has handled exits related to external
             * interrupts which must be addressed before allowing new
             * interrupts to come in).
             *
             * TODO: find out if this can also potentially context-switch us
             * and terminate in a reset_stack_and_jump(). (If it does, that
             * should be perfectly fine, but we should make a note of it in a
             * comment here as a notice to the reader, as we do above when
             * calling the soft IRQ handler.)
             */
            vmx_vmexit_handler(guest_regs);
        }
        else if ( vmrun_retval < 0 ) /* VM entry failure */
        {
            /* Re-enable interrupts. */
            local_irq_enable();

            /* Call Xen's VM-entry failure function. */
            vmx_vmentry_failure();

            /*
             * Process soft IRQs. (Xen's assembly does this unconditionally
             * in the event of a VM-exit failure. do_softirq() will correctly
             * handle the case where there aren't actually any pending soft
             * IRQs.)
             */
            do_softirq();

            /* Start the loop afresh to attempt VM entry again. */
            continue;
        }
        else /* This shouldn't happen */
        {
            /* Re-enable interrupts. */
            local_irq_enable();

            panic("vmx_do_vmentry_sva(): ERROR: sva_runvm() returned "
                  "nonsensical error code %d.\n", vmrun_retval);
        }

        /*
         * We have now handled the VM exit, and can go around the loop again
         * to re-enter the VM.
         */
    }
}
