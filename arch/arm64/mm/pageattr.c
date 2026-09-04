/*
 * Copyright (c) 2014, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>

#include <asm/pgtable.h>
#include <asm/tlbflush.h>

struct page_change_data {
	pgprot_t set_mask;
	pgprot_t clear_mask;
};

static int change_page_range(pte_t *ptep, pgtable_t token, unsigned long addr,
			void *data)
{
	struct page_change_data *cdata = data;
	pte_t pte = *ptep;

	pte_val(pte) &= ~pgprot_val(cdata->clear_mask);
	pte_val(pte) |= pgprot_val(cdata->set_mask);

	set_pte(ptep, pte);
	return 0;
}

static bool vmalloc_range_valid(unsigned long start, unsigned long end)
{
	struct vm_struct *area;
	unsigned long area_start;
	unsigned long area_size;

	if (start < MODULES_VADDR || end > MODULES_END)
		return false;

	area = find_vm_area((void *)start);
	if (!area || !(area->flags & VM_ALLOC))
		return false;

	area_start = (unsigned long)area->addr;
	area_size = area->size;
	if (area_size < PAGE_SIZE || area_start > ULONG_MAX - area_size ||
		start < area_start || area_start < MODULES_VADDR ||
		area_start + area_size > MODULES_END)
		return false;

	/* vm_struct->size includes the trailing guard page. */
	area_size -= PAGE_SIZE;
	return end <= area_start + area_size;
}

static int change_memory_common(unsigned long addr, int numpages,
				pgprot_t set_mask, pgprot_t clear_mask)
{
	unsigned long start = addr;
	unsigned long size;
	unsigned long end;
	int ret;
	struct page_change_data data;

	if (numpages < 0)
		return -EINVAL;
	if (!numpages)
		return 0;
	if ((unsigned long)numpages > ULONG_MAX / PAGE_SIZE)
		return -EINVAL;

	size = PAGE_SIZE * (unsigned long)numpages;

	/* The exported set_memory_* API counts whole pages from addr.  Rounding
	 * an unaligned address down would silently change a different range and
	 * leave the tail page untouched, so reject such requests instead. */
	if (!IS_ALIGNED(addr, PAGE_SIZE))
		return -EINVAL;
	if (size > ULONG_MAX - start)
		return -EINVAL;
	end = start + size;

	if ((!is_module_address(start) || !is_module_address(end - 1)) &&
	    !vmalloc_range_valid(start, end))
		return -EINVAL;

	data.set_mask = set_mask;
	data.clear_mask = clear_mask;

	ret = apply_to_page_range(&init_mm, start, size, change_page_range,
					&data);

	flush_tlb_kernel_range(start, end);
	return ret;
}

int set_memory_ro(unsigned long addr, int numpages)
{
	return change_memory_common(addr, numpages,
					__pgprot(PTE_RDONLY),
					__pgprot(PTE_WRITE));
}
EXPORT_SYMBOL_GPL(set_memory_ro);

int set_memory_rw(unsigned long addr, int numpages)
{
	return change_memory_common(addr, numpages,
					__pgprot(PTE_WRITE),
					__pgprot(PTE_RDONLY));
}
EXPORT_SYMBOL_GPL(set_memory_rw);

int set_memory_nx(unsigned long addr, int numpages)
{
	return change_memory_common(addr, numpages,
					__pgprot(PTE_PXN),
					__pgprot(0));
}
EXPORT_SYMBOL_GPL(set_memory_nx);

int set_memory_x(unsigned long addr, int numpages)
{
	return change_memory_common(addr, numpages,
					__pgprot(0),
					__pgprot(PTE_PXN));
}
EXPORT_SYMBOL_GPL(set_memory_x);
