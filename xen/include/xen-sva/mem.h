/******************************************************************************
 * include/xen-sva/mem.h
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

#ifndef _XEN_SVA_MEM_H
#define _XEN_SVA_MEM_H

#include <sva/secmem.h>

/**
 * Map SVA's static data into the secure memory area
 */
void __init map_sva_static_data(void);

/**
 * Hand off control of the MMU to SVA
 */
void __init init_sva_mmu(void);

/**
 * Get a pointer to a virtual address's page table entry
 *
 * @param virt_addr The virtual address for which to look up page table entries
 * @param level     The level of the page table which contains the entry (1-4)
 */
void *get_page_table_entry_sva(uintptr_t virt_addr, int level);

#endif /* _XEN_SVA_MEM_H */
