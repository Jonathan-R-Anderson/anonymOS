// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/types.h>
#include <linux/io.h>
#include <linux/platform_device.h>
#include <linux/dma-map-ops.h>
#include <linux/scatterlist.h>
#include <linux/mm.h>
#include <linux/msi.h>
#include <linux/irq.h>
#include <asm/host_ops.h>

static int lkl_pci_generic_read(struct pci_bus *bus, unsigned int devfn,
				int where, int size, u32 *val)
{
	if (devfn == 0 &&
	    lkl_ops->pci_ops->read(bus->sysdata, where, size, val) == size)
		return PCIBIOS_SUCCESSFUL;
	else
		return PCIBIOS_FUNC_NOT_SUPPORTED;
}

static int lkl_pci_generic_write(struct pci_bus *bus, unsigned int devfn,
				 int where, int size, u32 val)
{
	if (devfn == 0 &&
	    lkl_ops->pci_ops->write(bus->sysdata, where, size, &val) == size)
		return PCIBIOS_SUCCESSFUL;
	else
		return PCIBIOS_FUNC_NOT_SUPPORTED;
}

void __iomem *__pci_ioport_map(struct pci_dev *dev, unsigned long port,
			       unsigned int nr)
{
	panic("%s is not supported\n", __func__);
	return NULL;
}

static int lkl_pci_override_resource(struct pci_dev *dev, void *data)
{
	int i;
	struct resource *r;
	resource_size_t start, size;
	void *remapped_start;

	if (dev->devfn != 0)
		return 0;

	for (i = 0; i < PCI_NUM_RESOURCES; i++) {
		r = &dev->resource[i];

		if (!r->parent && r->start && r->flags) {
			dev_info(&dev->dev, "claiming resource %s/%d\n",
				 pci_name(dev), i);
			if (pci_claim_resource(dev, i)) {
				dev_err(&dev->dev,
					"Could not claim resource %s/%d!",
					pci_name(dev), i);
			}

			size = pci_resource_len(dev, i);

			if (pci_resource_flags(dev, i) & IORESOURCE_MEM) {
				remapped_start =
					lkl_ops->pci_ops->resource_alloc(
						dev->sysdata, size, i);
			} else {
				remapped_start = NULL;
			}

			if (remapped_start) {
				/* override values */
				start = (resource_size_t)remapped_start;
				pci_resource_start(dev, i) = start;
				pci_resource_end(dev, i) = start + size - 1;
			} else {
				/*
				 * A host library or the application could
				 * not handle the resource. Disable it
				 * not to be touched by drivers.
				 */
				pci_resource_flags(dev, i) |=
					IORESOURCE_DISABLED;
			}
		}
	}

	dev->irq = lkl_get_free_irq("pci");

	if (lkl_ops->pci_ops->irq_init(dev->sysdata, dev->irq) < 0)
		return -ENOMEM;

	return 0;
}

static int lkl_pci_remove_devices(struct pci_dev *dev, void *data)
{
	lkl_ops->pci_ops->remove(dev->sysdata);
	return 0;
}

static struct pci_ops lkl_pci_root_ops = {
	.read = lkl_pci_generic_read,
	.write = lkl_pci_generic_write,
};

static void *lkl_dma_alloc(struct device *dev, size_t size,
			   dma_addr_t *dma_handle, gfp_t gfp,
			   unsigned long attrs)
{
	void *vaddr = page_to_virt(alloc_pages(gfp, get_order(size)));
	*dma_handle = (dma_addr_t)lkl_ops->pci_ops->map_page(
		to_pci_dev(dev)->sysdata, vaddr, size);
	return vaddr;
}

static void lkl_dma_free(struct device *dev, size_t size, void *cpu_addr,
			 dma_addr_t dma_addr, unsigned long attrs)
{
	lkl_ops->pci_ops->unmap_page(to_pci_dev(dev)->sysdata, dma_addr, size);
	__free_pages(virt_to_page(cpu_addr), get_order(size));
}

static dma_addr_t lkl_dma_map_page(struct device *dev, struct page *page,
				   unsigned long offset, size_t size,
				   enum dma_data_direction dir,
				   unsigned long attrs)
{
	dma_addr_t dma_handle = (dma_addr_t)lkl_ops->pci_ops->map_page(
		to_pci_dev(dev)->sysdata, page_to_virt(page) + offset, size);
	if (dma_handle == 0)
		return DMA_MAPPING_ERROR;

	return dma_handle;
}

static void lkl_dma_unmap_page(struct device *dev, dma_addr_t dma_addr,
			       size_t size, enum dma_data_direction dir,
			       unsigned long attrs)
{
	lkl_ops->pci_ops->unmap_page(to_pci_dev(dev)->sysdata, dma_addr, size);
}

static int lkl_dma_map_sg(struct device *dev, struct scatterlist *sgl,
			  int nents, enum dma_data_direction dir,
			  unsigned long attrs)
{
	int i;
	struct scatterlist *sg;

	for_each_sg(sgl, sg, nents, i) {
		void *va;

		WARN_ON(!sg_page(sg));
		va = sg_virt(sg);
		sg_dma_address(sg) = (dma_addr_t)lkl_dma_map_page(
			dev, sg_page(sg), sg->offset, sg->length, dir, attrs);
		sg_dma_len(sg) = sg->length;
	}
	return nents;
}

static void lkl_dma_unmap_sg(struct device *dev, struct scatterlist *sgl,
			     int nents, enum dma_data_direction dir,
			     unsigned long attrs)
{
	int i;
	struct scatterlist *sg;

	for_each_sg(sgl, sg, nents, i)
		lkl_dma_unmap_page(dev, sg_dma_address(sg), sg_dma_len(sg), dir,
				   attrs);
}

static int lkl_dma_supported(struct device *dev, u64 mask)
{
	return 1;
}

static char *pcidev_name;

static int __init setup_pci_device(char *str)
{
	if (pcidev_name) {
		pr_info("The PCI driver supports only one PCI device.");
		pr_info("'%s' will be discarded.", str);
		return -1;
	}
	pcidev_name = str;
	return 0;
}

early_param("lkl_pci", setup_pci_device);

const struct dma_map_ops lkl_dma_ops = {
	.alloc = lkl_dma_alloc,
	.free = lkl_dma_free,
	.map_sg = lkl_dma_map_sg,
	.unmap_sg = lkl_dma_unmap_sg,
	.map_page = lkl_dma_map_page,
	.unmap_page = lkl_dma_unmap_page,
	.dma_supported = lkl_dma_supported,
};

static int lkl_pci_probe(struct platform_device *pdev)
{
	struct lkl_pci_dev *dev;
	struct pci_bus *bus;

	if (!lkl_ops->pci_ops || !pcidev_name)
		return -1;

	dev = lkl_ops->pci_ops->add(pcidev_name, (void *)memory_start,
				    memory_end - memory_start);
	if (!dev)
		return -1;

	bus = pci_scan_bus(0, &lkl_pci_root_ops, (void *)dev);
	if (!bus) {
		lkl_ops->pci_ops->remove(dev);
		return -1;
	}
	pci_walk_bus(bus, lkl_pci_override_resource, NULL);
	pci_bus_add_devices(bus);
	dev_set_drvdata(&pdev->dev, bus);

	return 0;
}

static void lkl_pci_shutdown(struct platform_device *pdev)
{
	struct pci_bus *bus = (struct pci_bus *)dev_get_drvdata(&pdev->dev);

	if (bus)
		pci_walk_bus(bus, lkl_pci_remove_devices, NULL);
}

static struct platform_driver lkl_pci_driver = {
	.driver = {
		.name = "lkl_pci",
	},
	.probe = lkl_pci_probe,
	.shutdown = lkl_pci_shutdown,
};

static int __init lkl_pci_init(void)
{
	int ret;
	struct platform_device *dev;

	/*register a platform driver*/
	ret = platform_driver_register(&lkl_pci_driver);
	if (ret != 0)
		return ret;

	dev = platform_device_alloc("lkl_pci", -1);
	if (!dev)
		return -ENOMEM;

	ret = platform_device_add(dev);
	if (ret != 0)
		goto error;

	return 0;
error:
	platform_device_put(dev);
	return ret;
}


/*
 * WiFi W1: MSI support.  The lkl arch has no MSI IRQ domain, so with
 * CONFIG_PCI_MSI_ARCH_FALLBACKS the PCI core calls this weak-override per MSI
 * descriptor.  We allocate an LKL irq, ask the host (EpinAnonymOS op9) for the
 * MSI message (address/data pointing at a native IDT vector on the BSP LAPIC),
 * program the device's MSI capability, and repoint the host IRQ-delivery thread
 * at this irq.  Needed by iwlwifi (the AX210 is MSI-X-native and raises no INTx).
 */
/*
 * EpinAnonymOS: REFUSE MSI-X so iwlwifi (gen2/AX210) falls back to a SINGLE MSI.  On-device proof
 * (2026-07-01): in MSI-X mode the device delivered ZERO interrupts to us (top HUD FIRES=0) — the
 * MSI-X table/auto-mask path never emits to our BSP vector — so the firmware's ALIVE + RX-notif
 * interrupts are lost and the RT-ucode alive times out (-110).  In SINGLE-MSI mode the same device
 * DID deliver (FIRES=1) and the fw signalled ALIVE in CSR_INT (0x3), which the legacy handler reads
 * directly.  So force single-MSI (the delivering path); the earlier single-MSI failure was only the
 * (now-fixed) IML jiffies-deadlock + the (now-reverted) broken BAR direct-map, NOT the MSI path.
 */
int arch_setup_msi_irqs(struct pci_dev *dev, int nvec, int type)
{
	struct msi_desc *desc;
	int ret;

	if (type == PCI_CAP_ID_MSIX)
		return -ENOSPC;

	msi_for_each_desc(desc, &dev->dev, MSI_DESC_NOTASSOCIATED) {
		ret = arch_setup_msi_irq(dev, desc);
		if (ret < 0)
			return ret;
		if (ret > 0)
			return -ENOSPC;
	}
	return 0;
}

int arch_setup_msi_irq(struct pci_dev *dev, struct msi_desc *desc)
{
	struct msi_msg msg;
	int irq;

	if (!lkl_ops->pci_ops || !lkl_ops->pci_ops->msi_setup)
		return -EINVAL;

	irq = lkl_get_free_irq("msi");
	if (irq < 0)
		return irq;

	msg.address_lo = (u32)lkl_ops->pci_ops->msi_setup(dev->sysdata, 0);
	msg.address_hi = (u32)lkl_ops->pci_ops->msi_setup(dev->sysdata, 1);
	msg.data       = (u32)lkl_ops->pci_ops->msi_setup(dev->sysdata, 2);

	desc->irq = irq;
	irq_set_msi_desc(irq, desc);
	pci_write_msi_msg(irq, &msg);

	/*
	 * CRITICAL (W1): msi_capability_init()/msix_capability_init() MASK every
	 * vector during setup (msi.c pci_msi_mask / msix_mask_all).  In the normal
	 * irqdomain flow the vector is UNMASKED later when the driver's request_irq
	 * starts the irq (irq_chip .irq_unmask = pci_msi_unmask_irq).  Our
	 * ARCH_FALLBACK path installs no such chip, so without this the vector stays
	 * MASKED forever -> the device can never deliver its MSI (observed: AX210
	 * firmware-alive never arrives, FIRES=0 on the host).  Unmask it explicitly.
	 */
	{
		struct irq_data *idata = irq_get_irq_data(irq);
		if (idata)
			pci_msi_unmask_irq(idata);
	}

	if (lkl_ops->pci_ops->irq_init)
		lkl_ops->pci_ops->irq_init(dev->sysdata, irq);

	dev_info(&dev->dev,
		 "lkl: MSI irq=%d addr=%08x:%08x data=%08x msix=%d can_mask=%d\n",
		 irq, msg.address_hi, msg.address_lo, msg.data,
		 desc->pci.msi_attrib.is_msix, desc->pci.msi_attrib.can_mask);
	return 0;
}

subsys_initcall(lkl_pci_init);
