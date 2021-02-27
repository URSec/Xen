/*
 * asid.c: ASID management
 * Copyright (c) 2007, Advanced Micro Devices, Inc.
 * Copyright (c) 2009, Citrix Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/percpu.h>
#include <asm/hvm/asid.h>

#include <sva/vmx_intrinsics.h>

/* Xen command-line option to enable ASIDs */
static int opt_asid_enabled = 1;
boolean_param("asid", opt_asid_enabled);

/*
 * ASIDs partition the physical TLB.  In the current implementation ASIDs are
 * introduced to reduce the number of TLB flushes.  Each time the guest's
 * virtual address space changes (e.g. due to an INVLPG, MOV-TO-{CR3, CR4}
 * operation), instead of flushing the TLB, a new ASID is assigned.  This
 * reduces the number of TLB flushes to at most 1/#ASIDs.  The biggest
 * advantage is that hot parts of the hypervisor's code and data retain in
 * the TLB.
 *
 * Sketch of the Implementation:
 *
 * ASIDs are a CPU-local resource.  As preemption of ASIDs is not possible,
 * ASIDs are assigned in a round-robin scheme.  To minimize the overhead of
 * ASID invalidation, at the time of a TLB flush,  ASIDs are tagged with a
 * 64-bit generation.  Only on a generation overflow the code needs to
 * invalidate all ASID information stored at the VCPUs with are run on the
 * specific physical processor.  This overflow appears after about 2^80
 * host processor cycles, so we do not optimize this case, but simply disable
 * ASID useage to retain correctness.
 */

/* Per-CPU ASID management. */
struct hvm_asid_data {
   uint64_t core_asid_generation;
   uint32_t next_asid;
   uint32_t max_asid;
   bool_t disabled;
};

static DEFINE_PER_CPU(struct hvm_asid_data, hvm_asid_data);

void hvm_asid_init(int nasids)
{
    static int8_t g_disabled = -1;
    struct hvm_asid_data *data = &this_cpu(hvm_asid_data);

    data->max_asid = nasids - 1;
    data->disabled = !opt_asid_enabled || (nasids <= 1);

    if ( g_disabled != data->disabled )
    {
        printk("HVM: ASIDs %sabled.\n", data->disabled ? "dis" : "en");
        if ( g_disabled < 0 )
            g_disabled = data->disabled;
    }

    /* Zero indicates 'invalid generation', so we start the count at one. */
    data->core_asid_generation = 1;

    /* Zero indicates 'ASIDs disabled', so we start the count at one. */
    data->next_asid = 1;
}

void hvm_asid_flush_vcpu_asid(struct hvm_vcpu_asid *asid)
{
#ifdef CONFIG_SVA
    /*
     * This function should never be called in CONFIG_SVA. Instead, its
     * upstream caller hvm_asid_flush_vcpu() calls the
     * sva_flush_vpid_single() intrinsic directly. This is necessary because
     * we need to know the SVA VM ID in order to pass it to that
     * intrinsic, and that information lives in struct vcpu, not its
     * sub-struct hvm_vcpu_asid (which is all we have access to here).
     *
     * Except in sva_flush_vpid_single(), Xen only calls this function
     * directly to support nested VMX, which we do not presently support in
     * Shade. (Adding such support in the future is likely doable but would
     * require digging into Xen's nested VMX code more deeply to figure out
     * how to integrate it with Shade.)
     */
    panic("hvm_asid_flush_vcpu_asid(): Unimplemented in CONFIG_SVA since "
        "only called directly in support of nested VMX, "
        "which we don't (yet) support.\n");
#else
    asid->generation = 0;
#endif
}

void hvm_asid_flush_vcpu(struct vcpu *v)
{
#ifdef CONFIG_SVA
    /*
     * SVA: we require the processor to have single-context INVVPID support
     * in our baseline, so we can just use that instead of Xen's roundabout
     * generational-increment scheme (which, so far as I can tell, is simply
     * a way of performantly implementing single-context INVVPID on systems
     * that may or may not support it directly).
     *
     * NOTE: we only perform the flush for the "outer" vCPU and ignore any
     * nested vCPU. This is because we do not yet support nested VMX in
     * CONFIG_SVA. Adding such support in the future is likely doable but
     * would require digging into Xen's nested VMX code more deeply to figure
     * out how to integrate it with Shade. In particular as this code here is
     * concerned, we have not yet ported the nested VMX code to use Shade
     * intrinsics for allocating and managing VMCSes, so the SVA VM ID that
     * we would need to pass to the sva_flush_vpid_single() intrinsic simply
     * doesn't exist.
     */

    /* Get the SVA VM ID corresponding to this VMCS address.
     *
     * FIXME: this is a temporary hack for incremental porting. Eventually,
     * we want Xen to not have the VMCS paddr pointer at all and instead
     * track the SVA VM ID directly. sva_get_vmid_from_vmcs() is a
     * brute-force solution (it does a linear search through SVA's VM
     * descriptor array until it finds one whose VMCS address matches that
     * provided) but it works "well enough" at this stage. */
    int sva_vmid = sva_get_vmid_from_vmcs(v->arch.hvm.vmx.vmcs_pa);

    sva_flush_vpid_single(sva_vmid,
        false /* don't retain global translations */);
#else
    hvm_asid_flush_vcpu_asid(&v->arch.hvm.n1asid);
    hvm_asid_flush_vcpu_asid(&vcpu_nestedhvm(v).nv_n2asid);
#endif
}

void hvm_asid_flush_core(void)
{
#ifdef CONFIG_SVA
    /*
     * SVA: we require the processor to have single-context INVVPID support
     * in our baseline, so we can just use that instead of Xen's roundabout
     * generational-increment scheme (which, so far as I can tell, is simply
     * a way of performantly implementing single-context INVVPID on systems
     * that may or may not support it directly).
     *
     * This means that we no longer have the ability to do a whole-pCPU ASID
     * flush by incrementing the generation, but that's fine because we can
     * achieve the same result with an all-contexts INVVPID.
     */
    sva_flush_vpid_all();
#else
    struct hvm_asid_data *data = &this_cpu(hvm_asid_data);

    if ( data->disabled )
        return;

    if ( likely(++data->core_asid_generation != 0) )
        return;

    /*
     * ASID generations are 64 bit.  Overflow of generations never happens.
     * For safety, we simply disable ASIDs, so correctness is established; it
     * only runs a bit slower.
     */
    printk("HVM: ASID generation overrun. Disabling ASIDs.\n");
    data->disabled = 1;
#endif
}

bool_t hvm_asid_handle_vmenter(struct hvm_vcpu_asid *asid)
{
#ifdef CONFIG_SVA
    /*
     * SVA: we require the processor to have single-context INVVPID support
     * in our baseline, so we can just use that instead of Xen's roundabout
     * generational-increment scheme (which, so far as I can tell, is simply
     * a way of performantly implementing single-context INVVPID on systems
     * that may or may not support it directly).
     *
     * This function only exists to support that scheme, and its upstream
     * call sites should be disabled in CONFIG_SVA. If we missed one this
     * panic should catch it.
     */
    panic("hvm_asid_handle_vmenter(): shouldn't be called in CONFIG_SVA\n");
#endif

    struct hvm_asid_data *data = &this_cpu(hvm_asid_data);

    /* On erratum #170 systems we must flush the TLB. 
     * Generation overruns are taken here, too. */
    if ( data->disabled )
        goto disabled;

    /* Test if VCPU has valid ASID. */
    if ( asid->generation == data->core_asid_generation )
        return 0;

    /* If there are no free ASIDs, need to go to a new generation */
    if ( unlikely(data->next_asid > data->max_asid) )
    {
        hvm_asid_flush_core();
        data->next_asid = 1;
        if ( data->disabled )
            goto disabled;
    }

    /* Now guaranteed to be a free ASID. */
    asid->asid = data->next_asid++;
    asid->generation = data->core_asid_generation;

    /*
     * When we assign ASID 1, flush all TLB entries as we are starting a new
     * generation, and all old ASID allocations are now stale. 
     */
    return (asid->asid == 1);

 disabled:
    asid->asid = 0;
    return 0;
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
