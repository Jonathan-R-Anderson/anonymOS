#include <string.h>
#include <stdint.h>
#include <lkl_host.h>

#include "iomem.h"

#define IOMEM_OFFSET_BITS		24
#define MAX_IOMEM_REGIONS		256

#define IOMEM_ADDR_TO_INDEX(addr) \
	(((uintptr_t)addr) >> IOMEM_OFFSET_BITS)
#define IOMEM_ADDR_TO_OFFSET(addr) \
	(((uintptr_t)addr) & ((1 << IOMEM_OFFSET_BITS) - 1))
#define IOMEM_INDEX_TO_ADDR(i) \
	(void *)(uintptr_t)(i << IOMEM_OFFSET_BITS)

static struct iomem_region {
	void *data;
	int size;
	const struct lkl_iomem_ops *ops;
	void *host_va;	/* EpinAnonymOS L6.1: non-NULL => DIRECT region. The BAR has been
			 * mapped straight into the host process (bridge op8) and host_va is
			 * the real CPU pointer; lkl_ioremap returns it so a GPU framebuffer
			 * is touched by plain memcpy (no per-access op3/op4, no 16MB cap). */
} iomem_regions[MAX_IOMEM_REGIONS];

void* register_iomem(void *data, int size, const struct lkl_iomem_ops *ops)
{
	int i;

	if (size > (1 << IOMEM_OFFSET_BITS) - 1)
		return NULL;

	/* EpinAnonymOS L6.1: a free slot needs BOTH ops==NULL AND host_va==NULL — a DIRECT
	 * region (register_iomem_direct) has ops==NULL but host_va set, and must NOT be reused
	 * (else a register BAR would collide with the framebuffer's token). */
	for (i = 1; i < MAX_IOMEM_REGIONS; i++)
		if (!iomem_regions[i].ops && !iomem_regions[i].host_va)
			break;

	if (i >= MAX_IOMEM_REGIONS)
		return NULL;

	iomem_regions[i].data = data;
	iomem_regions[i].size = size;
	iomem_regions[i].ops = ops;
	iomem_regions[i].host_va = NULL;
	return IOMEM_INDEX_TO_ADDR(i);
}

/* EpinAnonymOS L6.1: register a BAR that the host has ALREADY mapped directly into this
 * process (host_va = the real CPU pointer to the BAR, from bridge op8). Returns the usual
 * iomem token (so the driver's resource.start stays in token space and lkl_ioremap can find
 * the slot), but marks the region DIRECT. Skips the 16MB register_iomem size cap — a single
 * region's 24-bit offset space holds a 16MB framebuffer BAR (offsets 0..0xFFFFFF). */
void* register_iomem_direct(void *host_va, int size)
{
	int i;

	for (i = 1; i < MAX_IOMEM_REGIONS; i++)
		if (!iomem_regions[i].ops && !iomem_regions[i].host_va)
			break;

	if (i >= MAX_IOMEM_REGIONS)
		return NULL;

	iomem_regions[i].data = host_va;
	iomem_regions[i].size = size;
	iomem_regions[i].ops = NULL;		/* no routed ops — accessed directly */
	iomem_regions[i].host_va = host_va;	/* DIRECT marker */
	return IOMEM_INDEX_TO_ADDR(i);
}

void unregister_iomem(void *base)
{
	unsigned int index = IOMEM_ADDR_TO_INDEX(base);

	if (index >= MAX_IOMEM_REGIONS) {
		lkl_printf("%s: invalid iomem_addr %p\n", __func__, base);
		return;
	}

	iomem_regions[index].size = 0;
	iomem_regions[index].ops = NULL;
	iomem_regions[index].host_va = NULL;
}

void *lkl_ioremap(long addr, int size)
{
	int index = IOMEM_ADDR_TO_INDEX(addr);
	struct iomem_region *iomem;

	if (index <= 0 || index >= MAX_IOMEM_REGIONS)
		return NULL;
	iomem = &iomem_regions[index];

	/* EpinAnonymOS L6.1: a DIRECT region returns the REAL host VA. addr's low 24 bits
	 * carry the in-BAR offset (TTM ioremap_wc's the bo's offset within VRAM), so add it
	 * to host_va. The 16MB size cap does not apply (the BAR is real mapped memory). */
	if (iomem->host_va)
		return (void *)((char *)iomem->host_va + IOMEM_ADDR_TO_OFFSET(addr));

	if (iomem->ops && size <= iomem->size)
		return IOMEM_INDEX_TO_ADDR(index);

	return NULL;
}

int lkl_iomem_access(const volatile void *addr, void *res, int size, int write)
{
	int index = IOMEM_ADDR_TO_INDEX(addr);
	struct iomem_region *iomem = &iomem_regions[index];
	int offset = IOMEM_ADDR_TO_OFFSET(addr);
	int ret;

	if (index > MAX_IOMEM_REGIONS || !iomem_regions[index].ops ||
	    offset + size > iomem_regions[index].size)
		return -1;

	if (write)
		ret = iomem->ops->write(iomem->data, offset, res, size);
	else
		ret = iomem->ops->read(iomem->data, offset, res, size);

	return ret;
}
