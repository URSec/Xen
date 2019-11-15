/*******************************************************************************
 * Memory handling for SVA
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

#include <xen/domain_page.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/types.h>
#include <asm/page.h>

#include <sva/callbacks.h>
#include <sva/mmu_intrinsics.h>

#define SUPERPAGE_SIZE (1UL << SUPERPAGE_SHIFT)
#define SUPERPAGE_MASK (~(SUPERPAGE_SIZE - 1))
#define SUPERPAGE_ALIGN(x) (((x) + SUPERPAGE_SIZE - 1) & SUPERPAGE_MASK)

/* The FreeBSD port alloctated this in the linker script. Reason? */
unsigned char __used SVAPTPages[1024][PAGE_SIZE] __attribute__((section("svamem")));

uintptr_t provideSVAMemory(size_t size)
{
    /*
     * For now, we only support SVA requesting a single 4 kB page of memory
     * at a time from Xen. (This is in line with the FreeBSD port and how SVA
     * is currently written to utilize this callback function.)
     */
    if (size != 4096)
        panic("SVA: provideSVAMemory() only supports working with a single "
              "4 kB page of memory at a time. (Attempted to request %ld B.)\n",
              size);

    /*
     * Get a page of anonymous (not accounted to a particular domain) memory
     * from Xen's domain heap.
     *
     * This page will not be mapped anywhere except in Xen's direct map (and
     * of course SVA's direct map, once we set that up).
     */
    struct page_info *pg = alloc_domheap_page(NULL, 0);

    /*
     * TODO: remove the page from Xen's direct map. (SVA's MMU checks will
     * verify this to keep Xen honest.)
     *
     * We're not doing this at the moment because we don't yet have SVA's
     * DMAP working in the Xen port.
     */

    /* Return the physical address of the page. */
    return page_to_maddr(pg);
}

void releaseSVAMemory(uintptr_t addr, size_t size)
{
    /*
     * For now, we only support SVA requesting a single 4 kB page of memory
     * at a time from Xen. (This is in line with the FreeBSD port and how SVA
     * is currently written to utilize this callback function.)
     */
    if (size != 4096)
        panic("SVA: releaseSVAMemory() only supports working with a single "
              "4 kB page of memory at a time. (Attempted to free %ld B.)\n",
              size);

    /*
     * TODO: add the page back to Xen's direct map.
     *
     * We're not doing this at the moment because we don't yet have SVA's
     * DMAP working in the Xen port, and thus provideSVAMemory() isn't
     * removing pages from Xen's DMAP in the first place.
     */

    /* Return the page to Xen's domain heap. */
    free_domheap_page(maddr_to_page(addr));
}

void *get_page_table_entry_sva(uintptr_t virt_addr, int level) {
    switch (level) {
    case 1:
        return sva_get_l1_entry(virt_addr);
    case 2:
        return sva_get_l2_entry(virt_addr);
    case 3:
        return sva_get_l3_entry(virt_addr);
    case 4:
        return sva_get_l4_entry(virt_addr);
    default:
        BUG();
    }
}

void __init map_sva_static_data(void)
{
#ifndef NDEBUG
    printk("Mapping SVA static data into the secure memory area.\n");
#endif

    extern char __start_sva_data[], __end_sva_data[];
    /* Temporary workaround for small code model: The offset to
     * __start/end_sva_data is larger than 2GB, so we need a movabs to load the
     * address into a register. The only way to do that in the small/kernel code
     * models is to use inline assembly.
     */
    char *start, *end;
    asm ("movabsq $__start_sva_data, %0\n\t"
         "movabsq $__end_sva_data, %1"
         : "=r"(start), "=r"(end));

    for (char* addr = start; addr < end; addr += SUPERPAGE_SIZE) {
        struct page_info *pg = alloc_domheap_pages(NULL, SUPERPAGE_ORDER, 0);
        BUG_ON(!pg);
        unmap_domain_page(memset(__map_domain_page(pg), 0, SUPERPAGE_SIZE));
        int err = map_pages_to_xen((uintptr_t)addr,
                                   page_to_mfn(pg),
                                   SUPERPAGE_SIZE / PAGE_SIZE,
                                   PAGE_HYPERVISOR_RW);
        BUG_ON(err);
    }
}
