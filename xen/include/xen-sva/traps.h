/******************************************************************************
 * include/xen-sva/traps.h
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

#ifndef _XEN_SVA_TRAPS_H
#define _XEN_SVA_TRAPS_H

/**
 * Register Xen's exception and interrupt handlers with SVA
 */
void __init init_sva_traps(void);

/**
 * Create a bounce frame on the guest's stack.
 *
 * Will switch to guest kernel mode if the guest is currently in user mode.
 *
 * @param regs  The guest's saved registers
 * @param curr  The vCPU on which to create the bounce frame
 * @param tb    Information about the type of bounce frame to create
 */
void make_bounce_frame(struct cpu_user_regs *regs, struct vcpu *curr,
                       struct trap_bounce *tb);

#endif /* _XEN_SVA_TRAPS_H */
