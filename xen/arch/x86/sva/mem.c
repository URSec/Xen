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

#define SUPERPAGE_SIZE (1UL << SUPERPAGE_SHIFT)
#define SUPERPAGE_MASK (~(SUPERPAGE_SIZE - 1))
#define SUPERPAGE_ALIGN(x) (((x) + SUPERPAGE_SIZE - 1) & SUPERPAGE_MASK)

/* The FreeBSD port alloctated this in the linker script. Reason? */
unsigned char __used SVAPTPages[1024][PAGE_SIZE] __attribute__((section("svamem")));

uintptr_t provideSVAMemory(size_t size)
{
    // TODO
    return (uintptr_t)NULL;
}

void releaseSVAMemory(uintptr_t addr, size_t size)
{
    // TODO
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
